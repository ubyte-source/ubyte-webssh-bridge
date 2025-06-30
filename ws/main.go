package main

import (
	"flag"
	"log"

	"github.com/ubyte-source/ubyte-webssh-bridge/config"
	"github.com/ubyte-source/ubyte-webssh-bridge/server"
)

var (
	// Command line flags
	debugMode       bool
	listenAddress   string
	certificateFile string
	keyFile         string
)

// init initializes command-line flags
func init() {
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	flag.StringVar(&listenAddress, "address", ":8080", "Address to listen on")
	flag.StringVar(&certificateFile, "cert", "/data/certificate.crt", "Path to TLS certificate file")
	flag.StringVar(&keyFile, "key", "/data/certificate.key", "Path to TLS private key file")
	flag.Parse()
}

// main is the entry point of the application
func main() {
	// Create configuration
	cfg := config.DefaultConfiguration()

	// Override configuration with command line flags
	if debugMode {
		cfg.DebugMode = true
	}
	if listenAddress != "" {
		cfg.ListenAddress = listenAddress
	}
	if certificateFile != "" {
		cfg.CertificateFile = certificateFile
	}
	if keyFile != "" {
		cfg.KeyFile = keyFile
	}

	// Create and start the WebSSH bridge server
	bridge, err := server.NewWebSSHBridge(cfg)
	if err != nil {
		log.Fatalf("Failed to create WebSSH bridge: %v", err)
	}

	// Run the server (this will block until shutdown)
	if err := bridge.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
