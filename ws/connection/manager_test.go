package connection

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseTargetAddress(t *testing.T) {
	m := &ConnectionManager{}

	tests := []struct {
		name        string
		path        string
		expected    string
		expectError bool
	}{
		{"valid host and port", "/ws/host/22", "host:22", false},
		{"valid hostname with port", "/ws/example.com/443", "example.com:443", false},
		{"valid IP with port", "/ws/192.168.1.1/22", "192.168.1.1:22", false},
		{"missing port", "/ws/onlyhost", "", true},
		{"empty path", "", "", true},
		{"only ws", "/ws", "", true},
		{"root path", "/", "", true},
		{"too many parts", "/ws/host/22/extra", "host:22", false}, // should still work with extra parts
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{URL: &url.URL{Path: tt.path}}
			addr, err := m.ParseTargetAddress(req)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error for path %s", tt.path)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for path %s: %v", tt.path, err)
				}
				if addr != tt.expected {
					t.Fatalf("expected %s, got %s", tt.expected, addr)
				}
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	m := &ConnectionManager{}

	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
	}{
		{
			name:          "X-Forwarded-For single IP",
			remoteAddr:    "3.3.3.3:123",
			xForwardedFor: "1.1.1.1",
			expectedIP:    "1.1.1.1",
		},
		{
			name:          "X-Forwarded-For multiple IPs",
			remoteAddr:    "3.3.3.3:123",
			xForwardedFor: "1.1.1.1, 2.2.2.2",
			expectedIP:    "1.1.1.1",
		},
		{
			name:          "X-Forwarded-For with spaces",
			remoteAddr:    "3.3.3.3:123",
			xForwardedFor: " 1.1.1.1 , 2.2.2.2 ",
			expectedIP:    "1.1.1.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "3.3.3.3:123",
			xRealIP:    "2.2.2.2",
			expectedIP: "2.2.2.2",
		},
		{
			name:          "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:    "3.3.3.3:123",
			xForwardedFor: "1.1.1.1",
			xRealIP:       "2.2.2.2",
			expectedIP:    "1.1.1.1",
		},
		{
			name:       "RemoteAddr fallback",
			remoteAddr: "3.3.3.3:123",
			expectedIP: "3.3.3.3",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "3.3.3.3",
			expectedIP: "3.3.3.3",
		},
		{
			name:       "IPv6 RemoteAddr",
			remoteAddr: "[::1]:123",
			expectedIP: "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header:     http.Header{},
				RemoteAddr: tt.remoteAddr,
			}

			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := m.GetClientIP(req)
			if ip != tt.expectedIP {
				t.Fatalf("expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}
