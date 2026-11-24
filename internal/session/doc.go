// Package session serves one page over one WebSocket. Run waits for the page's connect
// message within the handshake timeout, dials the target through sshclient with the
// page as its Page, so the banners, the challenges and the sign requests reach the user
// and the answers come back, opens the shell, then carries terminal bytes both ways in
// binary frames and sends the exit. The password and the answers are dropped once the
// login ends. Run pings the page every 30 seconds, closes the WebSocket with the code
// that ends the session, and returns once every goroutine it started has ended.
package session
