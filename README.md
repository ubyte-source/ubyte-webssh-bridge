# Ubyte WebSSH Bridge

[![Go Version](https://img.shields.io/badge/Go-1.23+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://hub.docker.com/r/ubyte/ubyte-webssh-bridge)

Ubyte WebSSH Bridge is a high-performance, enterprise-grade WebSocket-to-SSH gateway that enables secure SSH connections directly from web browsers. Built with Go, it provides a robust, scalable solution for web-based terminal access with advanced features like connection management, rate limiting, health monitoring, and comprehensive security controls.

## 🏗️ Architecture Overview

```mermaid
graph TB
    subgraph "Client Layer"
        Browser["🌐 Web Browser"]
        Terminal["📟 xterm.js Terminal"]
    end

    subgraph "Frontend Layer"
        WebUI["🎨 Web Interface"]
        Auth["🔐 Authentication Form"]
    end

    subgraph "WebSocket Layer"
        WSServer["🔌 WebSocket Server"]
        TLS["🔒 TLS Termination"]
    end

    subgraph "Application Layer"
        ConnMgr["📊 Connection Manager"]
        RateLim["⏱️ Rate Limiter"]
        MsgProc["📨 Message Processor"]
        SessionMgr["🎯 Session Manager"]
    end

    subgraph "SSH Layer"
        SSHClient["🔧 SSH Client"]
        SSHTimeouts["⏰ Timeout Manager"]
    end

    Browser --> Terminal
    Terminal --> WebUI
    WebUI --> Auth
    Auth --> TLS
    TLS --> WSServer
    WSServer --> ConnMgr
    ConnMgr --> RateLim
    ConnMgr --> SessionMgr
    SessionMgr --> MsgProc
    MsgProc --> SSHClient
    SSHClient --> SSHTimeouts
```

## ✨ Key Features

- **🔐 Enterprise Security**: TLS encryption, rate limiting, connection limits, IP whitelisting
- **📊 Advanced Monitoring**: Health checks, metrics endpoints, structured logging
- **⚡ High Performance**: Configurable buffers, connection pooling, optimized timeouts
- **🔧 Flexible Configuration**: Environment variables, command-line options, validation
- **🌐 Modern Web Interface**: Responsive design, xterm.js integration, auto-resize
- **🔄 Session Management**: Connection limits, automatic cleanup, idle session timeouts, thread-safe operations

## 🚀 Architecture Highlights

The WebSSH Bridge is built on a foundation of modern Go practices, focusing on **engineering simplicity** and **performance optimization**:

- **🔧 Centralized Coordinator**: A channel-based coordinator manages all state, eliminating race conditions and simplifying concurrency.
- **⚡ Atomic State Machine**: Lock-free, atomic transitions for session states (`Created → Connecting → Active → Closing → Closed`) ensure high performance and prevent deadlocks.
- **🧹 Automatic Cleanup**: Idle sessions are automatically detected and cleaned up, preventing resource leaks.
- **🛡️ Robust Security**: From TLS encryption to dynamic origin checks and comprehensive input validation, security is a core design principle.
- **📊 Rich Observability**: Detailed health checks and metrics endpoints provide deep insight into the system's performance and status.

**👉 For detailed technical information:** [📖 Connection Architecture](ws/connection/)

## 🚀 Quick Start

### 1. Download & Run

```bash
# Download binary
wget https://github.com/ubyte-source/ubyte-webssh-bridge/releases/latest/download/ubyte-webssh-bridge
chmod +x ubyte-webssh-bridge

# Generate certificates
openssl req -x509 -newkey rsa:4096 -keyout certificate.key -out certificate.crt -days 365 -nodes

# Start server
./ubyte-webssh-bridge -cert=certificate.crt -key=certificate.key
```

### 2. Access Interface

Open `https://localhost:8080` and connect to SSH servers using:

```
https://localhost:8080/ws/{SSH_HOST}/{SSH_PORT}
```

### 3. Docker Deployment

```bash
docker run -d --name webssh-bridge -p 8443:8443 \
  -e COUNTRY="US" \
  -e STATE="California" \
  -e ORGANIZATION="Your Organization" \
  -e COMMON_NAME="your-domain.com" \
  ubyte/ubyte-webssh-bridge:latest
```

## 📚 Documentation

### 🔧 Core Components

| Component              | Description                                             | Documentation                       |
| ---------------------- | ------------------------------------------------------- | ----------------------------------- |
| **Server**             | HTTP/WebSocket server, TLS termination, request routing | [📖 ws/server/](ws/server/)         |
| **Configuration**      | System configuration, validation, environment variables | [📖 ws/config/](ws/config/)         |
| **Connection Manager** | Session lifecycle, connection limits, resource cleanup  | [📖 ws/connection/](ws/connection/) |
| **SSH Client**         | SSH connections, timeouts, RADIUS support               | [📖 ws/ssh/](ws/ssh/)               |
| **Message Processing** | WebSocket messages, protocol handling, action dispatch  | [📖 ws/message/](ws/message/)       |
| **Rate Limiting**      | IP-based rate limiting, whitelist management            | [📖 ws/utils/](ws/utils/)           |

### 🌐 Frontend & Integration

| Component               | Description                                | Documentation             |
| ----------------------- | ------------------------------------------ | ------------------------- |
| **Web Interface**       | HTML/CSS/JS frontend, xterm.js integration | [📖 frontend/](frontend/) |
| **Nginx Configuration** | Reverse proxy setup, load balancing        | [📖 nginx/](nginx/)       |

## ⚙️ Configuration

### Command Line Options

```bash
./ubyte-webssh-bridge \
  -server-address=":8443" \
  -server-cert="/path/to/cert.pem" \
  -server-key="/path/to/key.pem" \
  -server-debug=true \
  -conn-max-total=2000 \
  -conn-max-per-host=20 \
  -conn-timeout="60s" \
  -ssh-connect-timeout="15s" \
  -ssh-auth-timeout="60s" \
  -ssh-handshake-timeout="90s" \
  -ws-read-buffer=16384 \
  -ws-write-buffer=16384 \
  -ws-handshake-timeout="45s" \
  -ws-read-limit=1048576 \
  -rate-interval="5s" \
  -rate-burst=20 \
  -rate-per-ip=true \
  -rate-whitelist="127.0.0.1,10.0.0.1" \
  -server-shutdown-timeout="30s" \
  -health-enabled=true \
  -health-path="/health" \
  -metrics-enabled=true \
  -metrics-path="/metrics"
```

### Environment Variables

#### 🔧 Configuration by Category (UWSB\_ Prefixed)

```bash
# 🔌 Connection Settings
UWSB_CONN_TIMEOUT="60s"                            # Connection timeout
UWSB_CONN_MAX_TOTAL=2000                           # Maximum total connections
UWSB_CONN_MAX_PER_HOST=20                          # Maximum connections per host
UWSB_SESSION_IDLE_TIMEOUT="5m"                     # Idle session cleanup timeout

# 🏥 Health & Metrics Monitoring
UWSB_HEALTH_ENABLED=true                           # Enable health check endpoint
UWSB_HEALTH_PATH="/health"                         # Health check endpoint path
UWSB_METRICS_ENABLED=true                          # Enable metrics endpoint
UWSB_METRICS_PATH="/metrics"                       # Metrics endpoint path

# ⏱️ Rate Limiting
UWSB_RATE_BURST=20                                 # Rate limit burst size
UWSB_RATE_INTERVAL="5s"                            # Rate limit interval
UWSB_RATE_PER_IP=true                              # Enable per-IP rate limiting
UWSB_RATE_WHITELIST="127.0.0.1,10.0.0.1"          # Comma-separated IP whitelist

# 🖥️ Server Settings
UWSB_SERVER_ADDRESS=":8443"                        # Server listen address
UWSB_SERVER_CERT_FILE="/path/to/certificate.crt"  # TLS certificate path
UWSB_SERVER_DEBUG=true                             # Enable debug logging
UWSB_SERVER_KEY_FILE="/path/to/private.key"       # TLS private key path
UWSB_SERVER_SHUTDOWN_TIMEOUT="30s"                 # Graceful shutdown timeout

# 🔐 SSH Settings
UWSB_SSH_AUTH_TIMEOUT="60s"                        # SSH authentication timeout (RADIUS)
UWSB_SSH_CONNECT_TIMEOUT="15s"                     # SSH connection timeout
UWSB_SSH_HANDSHAKE_TIMEOUT="90s"                   # SSH handshake timeout

# 🌐 WebSocket Settings
UWSB_WS_HANDSHAKE_TIMEOUT="45s"                    # WebSocket handshake timeout
UWSB_WS_READ_BUFFER=16384                          # WebSocket read buffer size
UWSB_WS_READ_LIMIT=1048576                         # WebSocket read limit (bytes)
UWSB_WS_WRITE_BUFFER=16384                         # WebSocket write buffer size
```

#### 🐳 Docker Certificate Generation

```bash
# Certificate generation (Docker only)
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORGANIZATION="Your Organization"
COMMON_NAME="your-domain.com"

# Default SSH target (optional)
HOST="192.168.1.100"
PORT="22"
```

**👉 For complete configuration options:** [📖 Configuration Guide](ws/config/)

## 🔌 API Reference

### WebSocket Connection

```
wss://{server}:{port}/ws/{ssh_host}/{ssh_port}
```

### HTTP Endpoints

- `GET /health` - Health check and status
- `GET /metrics` - Performance metrics and statistics

**👉 For complete API documentation:** [📖 Server Documentation](ws/server/)

## 🐳 Deployment

### Docker Compose

```yaml
version: "3.8"
services:
  webssh-bridge:
    image: ubyte/ubyte-webssh-bridge:latest
    ports:
      - "8443:8443"
    environment:
      - COUNTRY=US
      - STATE=California
      - ORGANIZATION=Your Organization
      - COMMON_NAME=your-domain.com
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "https://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Production Checklist

- [ ] Valid TLS certificates installed
- [ ] Rate limiting configured
- [ ] Connection limits set
- [ ] Monitoring enabled
- [ ] Firewall rules configured
- [ ] SSH servers hardened

## 🔒 Security Features

- **🔐 TLS Encryption**: Mandatory HTTPS/WSS connections with strong, modern cipher suites.
- **🛡️ Dynamic Origin Check**: Automatic Cross-Site WebSocket Hijacking (CSWH) protection by validating the client's `Origin` header against the server's `Host` header.
- **⏱️ Rate Limiting**: Configurable per-IP with whitelist support.
- **📊 Connection Limits**: Global and per-host restrictions.
- **🛡️ Input Validation**: Comprehensive message validation.
- **📝 Audit Logging**: Structured logging with detailed events.

**👉 For security best practices:** [📖 Security Documentation](ws/server/#-security-features)

## 📊 Monitoring

### Health Check

```bash
curl -k https://localhost:8443/health
```

### Metrics

```bash
curl -k https://localhost:8443/metrics
```

**👉 For monitoring setup:** [📖 Server Monitoring](ws/server/#-monitoring-endpoints)

## 🛠️ Development

### Build from Source

```bash
git clone https://github.com/ubyte-source/ubyte-webssh-bridge.git
cd ubyte-webssh-bridge/ws
go build -o ubyte-webssh-bridge .
```

### Project Structure

```
ubyte-webssh-bridge/
├── README.md                # This documentation
├── LICENSE                  # MIT license
├── Dockerfile               # Docker configuration
├── frontend/                # Web interface [📖](frontend/)
├── nginx/                   # Reverse proxy config [📖](nginx/)
└── ws/                      # Go application source
    ├── main.go              # Application entry point
    ├── config/              # Configuration management [📖](ws/config/)
    ├── server/              # HTTP/WebSocket server [📖](ws/server/)
    ├── connection/          # Connection management [📖](ws/connection/)
    ├── message/             # Message processing [📖](ws/message/)
    ├── ssh/                 # SSH client [📖](ws/ssh/)
    └── utils/               # Utilities & rate limiting [📖](ws/utils/)
```

**👉 For development setup:** [📖 Development Guide](ws/config/#-testing-configuration)

## 🔧 Troubleshooting

### Common Issues

- **Connection Refused**: Check SSH server accessibility and firewall rules
- **Authentication Failed**: Verify credentials and SSH server settings
- **Rate Limited**: Check IP whitelist or increase rate limits
- **Certificate Errors**: Use valid certificates or add `-k` for testing

**👉 For detailed troubleshooting:** [📖 Connection Troubleshooting](ws/connection/#-troubleshooting)

## 🤝 Contributing

We welcome contributions! Areas of interest:

- **Security enhancements** and authentication methods
- **Performance optimizations** and scalability improvements
- **Protocol support** and WebSocket extensions
- **Documentation** and examples

### Getting Started

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Go Team** - Excellent programming language
- **Gorilla WebSocket** - High-performance WebSocket library
- **xterm.js** - Modern terminal emulation
- **Community** - Contributors and users

---

**⭐ Star this repository if you find it useful!**

For questions, issues, or contributions, visit our [GitHub repository](https://github.com/ubyte-source/ubyte-webssh-bridge).
