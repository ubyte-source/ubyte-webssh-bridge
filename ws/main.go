package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var (
	// debugMode determines whether debug logging is enabled.
	debugMode bool
	// listenAddress is the HTTP server's listening address.
	listenAddress string

	// attemptsLock and lastAttempt are used for connection throttling.
	attemptsLock sync.Mutex
	lastAttempt  = make(map[string]time.Time)
)

const attemptInterval = 2 * time.Second

/**
 * init initializes command-line flags and configures Logrus logging level.
 */
func init() {
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	flag.StringVar(&listenAddress, "address", ":8080", "Address to listen on")
	flag.Parse()

	// Configure Logrus logging level based on debug flag.
	if debugMode {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
}

/**
 * upgrader configures the WebSocket upgrade settings.
 */
var upgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	CheckOrigin: func(r *http.Request) bool {
		// The CheckOrigin is left open since multiple FQDNs are used.
		return true
	},
}

/**
 * Credentials holds SSH authentication information.
 */
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

/**
 * genericMessage represents a message with an action field.
 */
type genericMessage struct {
	Action string `json:"action"`
}

/**
 * resizeMessage represents a terminal resize command.
 */
type resizeMessage struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

/**
 * actionHandler defines the function type for handling action messages.
 */
type actionHandler func(*ssh.Session, []byte) error

var handlers = map[string]actionHandler{
	"resize": handleResize,
	"ping":   handlePing,
}

/**
 * debugLog logs messages only if debugMode is enabled.
 * @param level The log level label.
 * @param format The log format string.
 * @param args Additional arguments.
 */
func debugLog(level, format string, args ...interface{}) {
	if debugMode {
		logrus.Debugf("["+level+"] "+format, args...)
	}
}

/**
 * handleResize processes the terminal resize command.
 * @param session The SSH session.
 * @param message The JSON encoded message.
 * @return An error if any occurs during processing.
 */
func handleResize(session *ssh.Session, message []byte) error {
	var rm resizeMessage
	if err := json.Unmarshal(message, &rm); err != nil {
		return fmt.Errorf("error unmarshalling resize message: %v", err)
	}
	debugLog("INFO", "Resizing terminal to cols: %d, rows: %d", rm.Cols, rm.Rows)
	return session.WindowChange(rm.Rows, rm.Cols)
}

/**
 * handlePing processes the ping action.
 * @param session The SSH session.
 * @param message The JSON encoded message.
 * @return An error if any occurs during processing.
 */
func handlePing(session *ssh.Session, message []byte) error {
	debugLog("INFO", "Received ping action")
	return nil
}

/**
 * isAttemptAllowed checks if a new connection attempt from destIP is allowed.
 * @param destIP The destination IP address.
 * @return True if allowed, false otherwise.
 */
func isAttemptAllowed(destIP string) bool {
	last, exists := lastAttempt[destIP]
	return !exists || time.Since(last) > attemptInterval
}

/**
 * recordAttemptAndScheduleCleanup records an SSH connection attempt and schedules cleanup.
 * @param destIP The destination IP address.
 */
func recordAttemptAndScheduleCleanup(destIP string) {
	attemptsLock.Lock()
	lastAttempt[destIP] = time.Now()
	attemptsLock.Unlock()
	time.AfterFunc(attemptInterval, func() {
		attemptsLock.Lock()
		delete(lastAttempt, destIP)
		attemptsLock.Unlock()
	})
}

/**
 * canAttemptNow checks if a new SSH connection attempt can proceed.
 * @param destIP The destination IP address.
 * @return True if the attempt is allowed, false otherwise.
 */
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

/**
 * parseTargetAddress extracts the target SSH address from the URL path.
 * The expected format is: /ws/{host}/{port}
 * @param r The HTTP request.
 * @return The target address as a string or an error if the format is invalid.
 */
func parseTargetAddress(r *http.Request) (string, error) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		return "", fmt.Errorf("URL does not contain valid host and port")
	}
	return parts[2] + ":" + parts[3], nil
}

/**
 * newSSHConfig returns an SSH client configuration based on provided credentials.
 * @param creds The SSH credentials.
 * @return A pointer to the SSH client configuration.
 */
func newSSHConfig(creds Credentials) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: creds.Username,
		Auth: []ssh.AuthMethod{ssh.Password(creds.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Remains unchanged since target hosts are unknown.
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
			Ciphers: []string{
				"aes128-cbc",
				"aes192-cbc",
				"aes256-cbc",
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"3des-cbc",
			},
		},
	}
}

/**
 * setupSSHSession initializes a new SSH session by requesting a PTY and obtaining the necessary I/O pipes.
 * @param sshConn The SSH client connection.
 * @return The SSH session, stdin pipe, stdout pipe, and an error if any occurs.
 */
func setupSSHSession(sshConn *ssh.Client) (*ssh.Session, io.WriteCloser, io.Reader, error) {
	session, err := sshConn.NewSession()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create SSH session: %v", err)
	}

	ptyModes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 24, 80, ptyModes); err != nil {
		session.Close()
		return nil, nil, nil, fmt.Errorf("failed to request PTY: %v", err)
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, nil, nil, fmt.Errorf("failed to obtain stdin pipe: %v", err)
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, nil, nil, fmt.Errorf("failed to obtain stdout pipe: %v", err)
	}

	// Redirect stderr to stdout.
	session.Stderr = session.Stdout
	return session, stdinPipe, stdoutPipe, nil
}

/**
 * handleSSHOutputNoBuffer reads SSH stdout and immediately writes the data to the WebSocket.
 * This avoids buffering delays so each character is sent as soon as it is read.
 * @param ctx The context for cancellation.
 * @param ws The WebSocket connection.
 * @param stdoutPipe The SSH stdout pipe.
 */
func handleSSHOutputNoBuffer(ctx context.Context, ws *websocket.Conn, stdoutPipe io.Reader) {
	const bufferSize = 8192
	readBuf := make([]byte, bufferSize)
	for {
		// Check if context is cancelled.
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := stdoutPipe.Read(readBuf)
		if n > 0 {
			if err := ws.WriteMessage(websocket.BinaryMessage, readBuf[:n]); err != nil {
				debugLog("ERROR", "Error writing SSH output to WebSocket: %v", err)
				ws.Close()
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				debugLog("INFO", "SSH session closed (EOF).")
			} else {
				debugLog("ERROR", "Error reading SSH stdout: %v", err)
			}
			ws.Close()
			return
		}
	}
}

/**
 * handleWebSocketMessages reads messages from the WebSocket and processes them.
 * If the message is a structured action, the appropriate handler is invoked;
 * otherwise, the message is forwarded as raw SSH input.
 * @param ctx The context for cancellation.
 * @param ws The WebSocket connection.
 * @param stdinPipe The SSH session's stdin pipe.
 * @param session The SSH session.
 */
func handleWebSocketMessages(ctx context.Context, ws *websocket.Conn, stdinPipe io.WriteCloser, session *ssh.Session) {
	defer stdinPipe.Close()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, msg, err := ws.ReadMessage()
		if err != nil {
			debugLog("ERROR", "Error reading WebSocket message: %v", err)
			return
		}
		var genMsg genericMessage
		if err := json.Unmarshal(msg, &genMsg); err != nil {
			// If unmarshalling fails, treat the message as raw SSH input.
			if _, err := stdinPipe.Write(msg); err != nil {
				debugLog("ERROR", "Error writing raw SSH input: %v", err)
				return
			}
			continue
		}
		if handler, exists := handlers[genMsg.Action]; exists {
			if err := handler(session, msg); err != nil {
				debugLog("ERROR", "Error handling action %s: %v", genMsg.Action, err)
				return
			}
		} else {
			debugLog("INFO", "Unknown action received: %s", genMsg.Action)
		}
	}
	session.Close()
}

/**
 * keepAlive sends periodic ping messages over the WebSocket to keep the connection alive.
 * @param ctx The context for cancellation.
 * @param ws The WebSocket connection.
 */
func keepAlive(ctx context.Context, ws *websocket.Conn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ws.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				debugLog("ERROR", "Error sending ping: %v", err)
				ws.Close()
				return
			}
		}
	}
}

/**
 * dialSSH performs the SSH dial operation and sends the result to the provided channel.
 * @param targetAddr The target address.
 * @param sshConfig The SSH client configuration.
 * @param resultChan The channel to send the result.
 */
func dialSSH(targetAddr string, sshConfig *ssh.ClientConfig, resultChan chan<- sshDialResult) {
	client, err := ssh.Dial("tcp", targetAddr, sshConfig)
	resultChan <- sshDialResult{client: client, err: err}
}

/**
 * sshDialResult holds the result of an SSH dial operation.
 */
type sshDialResult struct {
	client *ssh.Client
	err    error
}

/**
 * connectSSH attempts to establish an SSH connection with a timeout.
 * @param targetAddr The target address.
 * @param sshConfig The SSH client configuration.
 * @param timeout The timeout duration.
 * @return The SSH client or an error if connection fails or times out.
 */
func connectSSH(targetAddr string, sshConfig *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	resultChan := make(chan sshDialResult, 1)
	go dialSSH(targetAddr, sshConfig, resultChan)
	select {
	case result := <-resultChan:
		return result.client, result.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout connecting to SSH server")
	}
}

/**
 * runWebSocketMessages is a dedicated function to run handleWebSocketMessages as a goroutine.
 * @param ctx The context for cancellation.
 * @param wg Pointer to the WaitGroup to signal completion.
 * @param ws The WebSocket connection.
 * @param stdinPipe The SSH session's stdin pipe.
 * @param session The SSH session.
 */
func runWebSocketMessages(ctx context.Context, wg *sync.WaitGroup, ws *websocket.Conn, stdinPipe io.WriteCloser, session *ssh.Session) {
	defer wg.Done()
	handleWebSocketMessages(ctx, ws, stdinPipe, session)
}

/**
 * runSSHOutput is a dedicated function to run handleSSHOutputNoBuffer as a goroutine.
 * @param ctx The context for cancellation.
 * @param wg Pointer to the WaitGroup to signal completion.
 * @param ws The WebSocket connection.
 * @param stdoutPipe The SSH session's stdout pipe.
 */
func runSSHOutput(ctx context.Context, wg *sync.WaitGroup, ws *websocket.Conn, stdoutPipe io.Reader) {
	defer wg.Done()
	handleSSHOutputNoBuffer(ctx, ws, stdoutPipe)
}

/**
 * runKeepAlive is a dedicated function to run keepAlive as a goroutine.
 * @param ctx The context for cancellation.
 * @param wg Pointer to the WaitGroup to signal completion.
 * @param ws The WebSocket connection.
 */
func runKeepAlive(ctx context.Context, wg *sync.WaitGroup, ws *websocket.Conn) {
	defer wg.Done()
	keepAlive(ctx, ws)
}

/**
 * handleWebSocket is the main HTTP handler that upgrades the connection to WebSocket,
 * reads SSH credentials, establishes an SSH connection, sets up the SSH session,
 * and launches dedicated goroutines to handle bidirectional communication.
 * @param w The HTTP response writer.
 * @param r The HTTP request.
 */
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	targetAddr, err := parseTargetAddress(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !canAttemptNow(targetAddr) {
		http.Error(w, "Please wait before trying again", http.StatusTooManyRequests)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.Errorf("WebSocket upgrade error: %v", err)
		return
	}
	defer ws.Close()
	ws.SetReadLimit(512 * 1024) // Maximum message size of 512 KB.
	ws.SetPingHandler(func(appData string) error {
		debugLog("INFO", "Received ping, sending pong")
		return ws.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(time.Second))
	})

	// Create a cancellable context to coordinate goroutines.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Read the initial message containing SSH credentials.
	_, initMsg, err := ws.ReadMessage()
	if err != nil {
		logrus.Errorf("Error reading initial message: %v", err)
		return
	}
	var creds Credentials
	if err := json.Unmarshal(initMsg, &creds); err != nil {
		logrus.Errorf("Error unmarshalling credentials: %v", err)
		return
	}

	sshConfig := newSSHConfig(creds)
	sshConn, err := connectSSH(targetAddr, sshConfig, 5*time.Second)
	if err != nil {
		logrus.Errorf("Error connecting to SSH server: %v", err)
		return
	}
	defer sshConn.Close()

	session, stdinPipe, stdoutPipe, err := setupSSHSession(sshConn)
	if err != nil {
		logrus.Errorf("Error setting up SSH session: %v", err)
		return
	}
	defer session.Close()

	var wg sync.WaitGroup
	wg.Add(3)
	go runWebSocketMessages(ctx, &wg, ws, stdinPipe, session)
	go runSSHOutput(ctx, &wg, ws, stdoutPipe)
	go runKeepAlive(ctx, &wg, ws)

	if err := session.Shell(); err != nil {
		debugLog("ERROR", "Error starting SSH shell: %v", err)
		return
	}
	session.Wait()

	// Cancel the context and wait for all goroutines to finish.
	cancel()
	wg.Wait()
}

/**
 * main is the entry point of the application.
 */
func main() {
	http.HandleFunc("/ws/", handleWebSocket)
	logrus.Infof("Secure server started on address %s", listenAddress)
	if err := http.ListenAndServeTLS(listenAddress, "/data/certificate.crt", "/data/certificate.key", nil); err != nil {
		logrus.Fatalf("ListenAndServeTLS error: %v", err)
	}
}
