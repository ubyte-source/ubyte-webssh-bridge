package connection

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseTargetAddress(t *testing.T) {
	m := &ConnectionManager{}
	req := &http.Request{URL: &url.URL{Path: "/ws/host/22"}}
	addr, err := m.ParseTargetAddress(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "host:22" {
		t.Fatalf("expected host:22 got %s", addr)
	}
	req.URL.Path = "/ws/onlyhost"
	if _, err := m.ParseTargetAddress(req); err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestGetClientIP(t *testing.T) {
	m := &ConnectionManager{}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "3.3.3.3:123"}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	if ip := m.GetClientIP(req); ip != "1.1.1.1" {
		t.Fatalf("unexpected ip %s", ip)
	}
	req = &http.Request{Header: http.Header{}, RemoteAddr: "3.3.3.3:123"}
	req.Header.Set("X-Real-IP", "2.2.2.2")
	if ip := m.GetClientIP(req); ip != "2.2.2.2" {
		t.Fatalf("unexpected ip %s", ip)
	}
	req = &http.Request{RemoteAddr: "3.3.3.3:123"}
	if ip := m.GetClientIP(req); ip != "3.3.3.3" {
		t.Fatalf("unexpected ip %s", ip)
	}
}
