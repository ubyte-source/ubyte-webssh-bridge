package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubyte-source/ubyte-webssh-bridge/config"
)

func TestNewWebSSHBridge(t *testing.T) {
	cfg := config.DefaultConfiguration()
	bridge, err := NewWebSSHBridge(cfg)
	require.NoError(t, err)
	assert.NotNil(t, bridge)
	assert.Equal(t, cfg, bridge.config)
	assert.NotNil(t, bridge.logger)
	assert.NotNil(t, bridge.connectionManager)
	assert.NotNil(t, bridge.rateLimiter)
}

func TestNewWebSSHBridge_InvalidConfig(t *testing.T) {
	cfg := &config.Configuration{
		ListenAddress: "", // Invalid empty address
	}
	bridge, err := NewWebSSHBridge(cfg)
	assert.Error(t, err)
	assert.Nil(t, bridge)
}
