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
    // certificateFile and keyFile are the paths to the TLS certificate and key files.
    certificateFile string
    keyFile         string
    // attemptsLock and lastAttempt are used for connection throttling.
    attemptsLock sync.Mutex
    lastAttempt  = make(map[string]time.Time)
)

const attemptInterval = 2 * time.Second

/**
 * init initializes command-line flags and configures Logrus logging level.
 */
func init() {
	// debugMode is a command-line flag to enable verbose logging.
    flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	// listenAddress is the address to listen on
    flag.StringVar(&listenAddress, "address", ":8080", "Address to listen on")
	// TLS certificate and key file paths
    flag.StringVar(&certificateFile, "cert", "/data/certificate.crt", "Path to TLS certificate file")
    flag.StringVar(&keyFile, "key", "/data/certificate.key", "Path to TLS private key file")
	// Parse command-line flags
    flag.Parse()
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
    CheckOrigin:     func(r *http.Request) bool { return true },
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
 * canAttemptNow checks if a new SSH connection attempt can proceed.
 * @param destIP The destination IP address.
 * @return True if the attempt is allowed, false otherwise.
 */
func canAttemptNow(destIP string) bool {
    attemptsLock.Lock()
    allowed := isAttemptAllowed(destIP)
    if allowed {
        lastAttempt[destIP] = time.Now()
    }
    attemptsLock.Unlock()
    if allowed {
        time.AfterFunc(attemptInterval, func() {
            attemptsLock.Lock()
            delete(lastAttempt, destIP)
            attemptsLock.Unlock()
        })
    }
    return allowed
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
    modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
    if err := session.RequestPty("xterm", 24, 80, modes); err != nil {
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
    buffer := make([]byte, 8192)
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        n, err := stdoutPipe.Read(buffer)
        if n > 0 {
            if err := ws.WriteMessage(websocket.BinaryMessage, buffer[:n]); err != nil {
                debugLog("ERROR", "Error writing SSH output: %v", err)
                ws.Close()
                return
            }
        }
        if err != nil {
            if err != io.EOF {
                debugLog("ERROR", "Error reading SSH stdout: %v", err)
            }
            ws.Close()
            return
        }
    }
}

/**
 * handleWebSocketMessages reads messages from the WebSocket and processes them.
 * It delegates to helper functions to keep each step simple.
 * @param ctx The context for cancellation.
 * @param ws The WebSocket connection.
 * @param stdinPipe The SSH session's stdin pipe.
 * @param session The SSH session.
 */
func handleWebSocketMessages(ctx context.Context, ws *websocket.Conn, stdinPipe io.WriteCloser, session *ssh.Session) {
    defer stdinPipe.Close()
    for {
        mt, r, err := readNextFrame(ws, ctx)
        if err != nil {
            debugLog("ERROR", "WebSocket frame error: %v", err)
            return
        }
        if err := handleFrame(mt, r, stdinPipe, session); err != nil {
            debugLog("ERROR", "Frame processing error: %v", err)
            return
        }
    }
}

/**
 * readNextFrame reads the next WebSocket frame, unblocking on ctx cancellation.
 * @param ws The WebSocket connection.
 * @param ctx The context to observe.
 * @return The message type, payload reader, or an error.
 */
func readNextFrame(ws *websocket.Conn, ctx context.Context) (int, io.Reader, error) {
    go func() { <-ctx.Done(); ws.Close() }()
    return ws.NextReader()
}

/**
 * handleFrame dispatches the given frame to the proper handler.
 * @param mt The frame message type.
 * @param r The frame payload reader.
 * @param stdin The SSH stdin writer.
 * @param session The SSH session for action handlers.
 * @return An error if processing fails.
 */
func handleFrame(mt int, r io.Reader, stdin io.Writer, session *ssh.Session) error {
    switch mt {
    case websocket.BinaryMessage:
        return handleBinaryFrame(r, stdin)
    case websocket.TextMessage:
        return handleTextFrame(r, stdin, session)
    default:
        return nil
    }
}

/**
 * handleBinaryFrame pipes all binary data directly to SSH stdin.
 * @param r The source reader (binary payload).
 * @param w The destination writer (SSH stdin).
 * @return An error if piping fails.
 */
func handleBinaryFrame(r io.Reader, w io.Writer) error {
    _, err := io.Copy(w, r)
    return err
}

/**
 * handleTextFrame reads up to 4KB of text, tries JSON‐unmarshal,
 * invoking the action handler or writing raw to SSH stdin.
 * @param r The source reader (text payload).
 * @param w The SSH stdin writer.
 * @param session The SSH session for action handlers.
 * @return An error if processing fails.
 */
func handleTextFrame(r io.Reader, w io.Writer, session *ssh.Session) error {
    data, err := io.ReadAll(io.LimitReader(r, 4096))
    if err != nil {
        return err
    }
    var gm genericMessage
    if err := json.Unmarshal(data, &gm); err != nil {
        _, werr := w.Write(data)
        return werr
    }
    if h, ok := handlers[gm.Action]; ok {
        return h(session, data)
    }
    debugLog("INFO", "Unknown action: %s", gm.Action)
    return nil
}

/**
 * runWebSocketMessages runs handleWebSocketMessages as a goroutine.
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
 * runSSHOutput runs handleSSHOutputNoBuffer as a goroutine.
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
 * runKeepAlive runs keepAlive as a goroutine.
 * @param ctx The context for cancellation.
 * @param wg Pointer to the WaitGroup to signal completion.
 * @param ws The WebSocket connection.
 */
func runKeepAlive(ctx context.Context, wg *sync.WaitGroup, ws *websocket.Conn) {
    defer wg.Done()
    keepAlive(ctx, ws)
}

/**
 * sshDialResult holds the result of an SSH dial operation.
 */
type sshDialResult struct {
    client *ssh.Client
    err    error
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
            if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
                debugLog("ERROR", "Error sending ping: %v", err)
                ws.Close()
                return
            }
        }
    }
}

/**
 * handleWebSocket is the main HTTP handler that upgrades the connection to WebSocket,
 * reads SSH credentials, establishes an SSH connection, sets up the SSH session,
 * and launches dedicated goroutines to handle bidirectional communication.
 * Cleanup of SSH session, pipes, goroutines, and WebSocket is done in logical cascade.
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
    ws.SetReadLimit(512 * 1024)
    ws.SetPingHandler(func(appData string) error {
        debugLog("INFO", "Received ping, sending pong")
        return ws.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
    })
    // Read SSH credentials
    _, initMsg, err := ws.ReadMessage()
    if err != nil {
        ws.Close()
        logrus.Errorf("Error reading initial message: %v", err)
        return
    }
    var creds Credentials
    if err := json.Unmarshal(initMsg, &creds); err != nil {
        ws.Close()
        logrus.Errorf("Error unmarshalling credentials: %v", err)
        return
    }
    // Dial SSH
    sshConfig := newSSHConfig(creds)
    sshConn, err := connectSSH(targetAddr, sshConfig, 5*time.Second)
    if err != nil {
        ws.Close()
        logrus.Errorf("Error connecting to SSH server: %v", err)
        return
    }
    defer sshConn.Close()
    // Setup SSH session and pipes
    session, stdinPipe, stdoutPipe, err := setupSSHSession(sshConn)
    if err != nil {
        ws.Close()
        logrus.Errorf("Error setting up SSH session: %v", err)
        return
    }
    defer session.Close()
    // Coordinate cancellation
    ctx, cancel := context.WithCancel(context.Background())
    var wg sync.WaitGroup
    wg.Add(3)
    go runWebSocketMessages(ctx, &wg, ws, stdinPipe, session)
    go runSSHOutput(ctx, &wg, ws, stdoutPipe)
    go runKeepAlive(ctx, &wg, ws)
    if err := session.Shell(); err != nil {
        cancel()
        wg.Wait()
        ws.Close()
        debugLog("ERROR", "Error starting SSH shell: %v", err)
        return
    }
    session.Wait()
    cancel()
    wg.Wait()
    ws.Close()
}

/**
 * main is the entry point of the application.
 */
func main() {
    http.HandleFunc("/ws/", handleWebSocket)
    logrus.Infof("Secure server started on address %s", listenAddress)
    if err := http.ListenAndServeTLS(listenAddress, certificateFile, keyFile, nil); err != nil {
        logrus.Fatalf("ListenAndServeTLS error: %v", err)
    }
}
