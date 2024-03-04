// Package main implements a WebSocket-based SSH client.
// It supports resizing the terminal, handling SSH sessions,
// and user authentication via WebSockets.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// Global variables are documented directly above their declaration.
// debugMode indicates if the server is running in debug mode.
var debugMode bool

// listenAddress specifies the server address to listen on.
var listenAddress string

// attemptsLock is a mutex for synchronizing access to lastAttempt.
var attemptsLock sync.Mutex

// lastAttempt tracks the last attempt time for SSH connections by IP address.
var lastAttempt = make(map[string]time.Time)

// attemptInterval defines the cooldown period between attempts from the same IP.
const attemptInterval = 2 * time.Second

// init initializes command line flags and parses them.
func init() {
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	flag.StringVar(&listenAddress, "address", ":8080", "Address to listen on")
	flag.Parse()
}

// upgrader is a WebSocket upgrader configuration that allows any origin.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Credentials represents the username and password for SSH authentication.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// genericMessage represents a generic action to be performed.
type genericMessage struct {
	Action string `json:"action"`
}

// resizeMessage represents a request to resize the terminal.
type resizeMessage struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// actionHandler defines a function type for handling actions.
type actionHandler func(*ssh.Session, []byte) error

// handlers maps action strings to their corresponding handler functions.
var handlers = map[string]actionHandler{
	"resize": handleResize,
}

// debugLog logs debug messages if debug mode is enabled.
// @param level the log level (e.g., "INFO", "ERROR").
// @param format the format string for the log message.
// @param args the arguments to format into the log message.
func debugLog(level, format string, args ...interface{}) {
	if debugMode {
		log.Printf("%s: "+format, append([]interface{}{level}, args...)...)
	}
}

// handleResize handles terminal resize requests.
// @param session the SSH session to resize.
// @param message the resize message containing new dimensions.
// @return error indicating success or failure of the resize operation.
func handleResize(session *ssh.Session, message []byte) error {
	var resizeMsg resizeMessage
	if err := json.Unmarshal(message, &resizeMsg); err != nil {
		return fmt.Errorf("error unmarshalling resize message: %v", err)
	}
	debugLog("INFO", "Resizing to cols: %d, rows: %d", resizeMsg.Cols, resizeMsg.Rows)
	return session.WindowChange(resizeMsg.Rows, resizeMsg.Cols)
}

// isAttemptAllowed checks if a new attempt is allowed from the given IP address.
// @param destIP the IP address to check.
// @return bool indicating if an attempt is allowed.
func isAttemptAllowed(destIP string) bool {
	last, exists := lastAttempt[destIP]
	if !exists || time.Since(last) > attemptInterval {
		return true
	}
	return false
}

// recordAttemptAndScheduleCleanup records a new attempt and schedules its cleanup.
// @param destIP the IP address of the attempt.
func recordAttemptAndScheduleCleanup(destIP string) {
	attemptsLock.Lock()
	defer attemptsLock.Unlock()

	lastAttempt[destIP] = time.Now()
	time.AfterFunc(attemptInterval, func() {
		attemptsLock.Lock()
		delete(lastAttempt, destIP)
		attemptsLock.Unlock()
	})
}

// canAttemptNow checks if a new attempt can be made now, and records it if so.
// @param destIP the IP address of the attempt.
// @return bool indicating if the attempt can proceed.
func canAttemptNow(destIP string) bool {
	attemptsLock.Lock()
	allowed := isAttemptAllowed(destIP)
	attemptsLock.Unlock()

	if allowed {
		recordAttemptAndScheduleCleanup(destIP)
		return true
	}
	return false
}

// handleWebSocket handles incoming WebSocket connections for SSH session management.
// @param w the HTTP response writer.
// @param r the HTTP request containing the WebSocket upgrade request.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	pathSegments := strings.Split(r.URL.Path, "/")
	if len(pathSegments) < 4 {
		http.Error(w, "URL does not contain valid host and port", http.StatusBadRequest)
		return
	}
	host, port := pathSegments[2], pathSegments[3]
	sshAddr := host + ":" + port

	if !canAttemptNow(sshAddr) {
		http.Error(w, "Please wait before trying again", http.StatusTooManyRequests)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer ws.Close()

	_, msg, err := ws.ReadMessage()
	if err != nil {
		log.Printf("Error reading WebSocket message: %v", err)
		return
	}

	var creds Credentials
	if err := json.Unmarshal(msg, &creds); err != nil {
		log.Printf("Error unmarshalling credentials: %v", err)
		return
	}

	sshConfig := &ssh.ClientConfig{
		User:            creds.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(creds.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha1",
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group-exchange-sha1",
			},
		},
	}

	sshConn, err := ssh.Dial("tcp", sshAddr, sshConfig)
	if err != nil {
		log.Printf("Error connecting to SSH: %v", err)
		return
	}
	defer sshConn.Close()

	session, err := sshConn.NewSession()
	if err != nil {
		log.Printf("Error creating SSH session: %v", err)
		return
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 24, 80, modes); err != nil {
		debugLog("ERROR", "Error requesting pty: %v", err)
		return
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		debugLog("ERROR", "Error obtaining stdin pipe: %v", err)
		return
	}
	defer stdinPipe.Close()

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		debugLog("ERROR", "Error obtaining stdout pipe: %v", err)
		return
	}

	session.Stderr = session.Stdout

	go handleWebSocketMessages(ws, stdinPipe, session)
	go handleSSHOutput(ws, stdoutPipe)

	if err := session.Shell(); err != nil {
		debugLog("ERROR", "Error starting shell: %v", err)
		return
	}
	session.Wait()
}

// handleWebSocketMessages reads messages from the WebSocket and handles them.
// @param ws the WebSocket connection.
// @param stdinPipe the stdin pipe of the SSH session.
// @param session the SSH session.
func handleWebSocketMessages(ws *websocket.Conn, stdinPipe io.WriteCloser, session *ssh.Session) {
	defer stdinPipe.Close()

	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			debugLog("ERROR", "WebSocket message read error: %v", err)
			break
		}

		var genMsg genericMessage
		if err := json.Unmarshal(message, &genMsg); err != nil {
			if _, err := stdinPipe.Write(message); err != nil {
				debugLog("ERROR", "Error sending input to SSH: %v", err)
				break
			}
			continue
		}

		if handler, exists := handlers[genMsg.Action]; exists {
			if err := handler(session, message); err != nil {
				debugLog("ERROR", "Error handling %s action: %v", genMsg.Action, err)
				break
			}
		} else {
			debugLog("INFO", "Unknown action: %s", genMsg.Action)
		}
	}

	session.Close()
}

// handleSSHOutput forwards SSH session output to the WebSocket.
// @param ws the WebSocket connection.
// @param stdoutPipe the stdout pipe of the SSH session.
func handleSSHOutput(ws *websocket.Conn, stdoutPipe io.Reader) {
	buf := make([]byte, 1024)
	for {
		n, err := stdoutPipe.Read(buf)
		if err != nil {
			if err == io.EOF {
				debugLog("INFO", "SSH session closed.")
			} else {
				debugLog("ERROR", "Error reading SSH output: %v", err)
			}
			ws.Close()
			break
		}
		if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			debugLog("ERROR", "Error sending output to WebSocket: %v", err)
			ws.Close()
			break
		}
	}
}

// main is the entry point of the application.
func main() {
	http.HandleFunc("/ws/", handleWebSocket)
	log.Printf("Server started on address %s", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
