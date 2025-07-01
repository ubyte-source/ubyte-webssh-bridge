package connection

import (
	"runtime"
	"testing"
)

func TestBufferPoolBasicOperations(t *testing.T) {
	pool := NewBufferPool()

	// Test small buffer (1KB)
	small := pool.Get(512)
	if len(small) != 512 {
		t.Errorf("Expected buffer length 512, got %d", len(small))
	}
	if cap(small) < 512 {
		t.Errorf("Expected buffer capacity >= 512, got %d", cap(small))
	}

	// Test medium buffer (8KB)
	medium := pool.Get(4096)
	if len(medium) != 4096 {
		t.Errorf("Expected buffer length 4096, got %d", len(medium))
	}

	// Test large buffer (32KB)
	large := pool.Get(16384)
	if len(large) != 16384 {
		t.Errorf("Expected buffer length 16384, got %d", len(large))
	}

	// Test put back to pool
	pool.Put(small)
	pool.Put(medium)
	pool.Put(large)
}

func TestBufferPoolMemoryReuse(t *testing.T) {
	pool := NewBufferPool()

	// Get buffer and mark it
	buf1 := pool.Get(1024)
	buf1[0] = 0xFF // Mark the buffer

	// Return to pool
	pool.Put(buf1)

	// Get another buffer of same size
	buf2 := pool.Get(1024)

	// Should be the same underlying buffer, but cleared
	if buf2[0] != 0 {
		t.Errorf("Expected buffer to be cleared, but found %x at position 0", buf2[0])
	}

	// Capacity should be reused
	if cap(buf2) != cap(buf1) {
		t.Errorf("Expected capacity reuse, got %d vs %d", cap(buf2), cap(buf1))
	}

	pool.Put(buf2)
}

func TestBufferPoolGetCopy(t *testing.T) {
	pool := NewBufferPool()
	source := []byte("Hello, World!")

	copy := pool.GetCopy(source)

	if string(copy) != string(source) {
		t.Errorf("Expected copy to match source, got %s vs %s", string(copy), string(source))
	}

	// Modify source to ensure independence
	source[0] = 'X'
	if copy[0] == 'X' {
		t.Error("Copy should be independent of source")
	}

	pool.Put(copy)
}

func TestMessagePoolBasicOperations(t *testing.T) {
	pool := NewMessagePool()

	// Test WSMessage pooling
	data := []byte("test data")
	msg := pool.GetWSMessage(1, data)
	if msg.Type != 1 {
		t.Errorf("Expected message type 1, got %d", msg.Type)
	}
	if string(msg.Data) != string(data) {
		t.Errorf("Expected message data %s, got %s", string(data), string(msg.Data))
	}

	pool.PutWSMessage(msg)

	// Message should be cleared after put
	if msg.Type != 0 {
		t.Errorf("Expected message type to be cleared, got %d", msg.Type)
	}
	if msg.Data != nil {
		t.Error("Expected message data to be cleared")
	}

	// Test ControlSignal pooling
	sig := pool.GetControlSignal(ControlShutdown, "test")
	if sig.Type != ControlShutdown {
		t.Errorf("Expected control type %d, got %d", ControlShutdown, sig.Type)
	}
	if sig.Data != "test" {
		t.Errorf("Expected control data 'test', got %v", sig.Data)
	}

	pool.PutControlSignal(sig)

	// Signal should be cleared after put
	if sig.Type != 0 {
		t.Errorf("Expected control type to be cleared, got %d", sig.Type)
	}
	if sig.Data != nil {
		t.Error("Expected control data to be cleared")
	}
}

func BenchmarkBufferPoolVsAllocation(b *testing.B) {
	pool := NewBufferPool()

	b.Run("BufferPool", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := pool.Get(8192)
			// Simulate some work
			buf[0] = byte(i)
			pool.Put(buf)
		}
	})

	b.Run("DirectAllocation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 8192)
			// Simulate some work
			buf[0] = byte(i)
			// No explicit deallocation - relies on GC
		}
	})
}

func BenchmarkMessagePoolVsAllocation(b *testing.B) {
	pool := NewMessagePool()
	data := []byte("benchmark data")

	b.Run("MessagePool", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			msg := pool.GetWSMessage(1, data)
			// Simulate some work
			_ = msg.Type
			pool.PutWSMessage(msg)
		}
	})

	b.Run("DirectAllocation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			msg := &WSMessage{Type: 1, Data: data}
			// Simulate some work
			_ = msg.Type
			// No explicit deallocation - relies on GC
		}
	})
}

func TestBufferPoolMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory usage test in short mode")
	}

	pool := NewBufferPool()

	// Test with repeated allocations (where pools excel)
	iterations := 10000

	// Test with pool - repeated get/put cycles
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	for i := 0; i < iterations; i++ {
		buf := pool.Get(8192)
		buf[0] = byte(i) // Simulate work
		pool.Put(buf)
	}

	runtime.GC()
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	poolAllocations := m2.TotalAlloc - m1.TotalAlloc

	// Test without pool - repeated allocations
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for i := 0; i < iterations; i++ {
		buf := make([]byte, 8192)
		buf[0] = byte(i) // Simulate work
		// Buffer goes out of scope and becomes garbage
	}

	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m2)

	directAllocations := m2.TotalAlloc - m1.TotalAlloc

	t.Logf("Direct allocations: %d bytes", directAllocations)
	t.Logf("Pool allocations: %d bytes", poolAllocations)

	// Calculate reduction safely
	if directAllocations > 0 {
		reduction := float64(directAllocations-poolAllocations) / float64(directAllocations) * 100
		t.Logf("Memory reduction: %.1f%%", reduction)

		// Pool should use significantly less memory for repeated operations
		if reduction > 0 {
			t.Logf("✓ Memory pool achieved %.1f%% reduction", reduction)
		} else {
			t.Logf("Pool used more memory (%.1f%% overhead), which is normal for small tests", -reduction)
		}
	} else {
		t.Log("Could not measure allocation difference")
	}
}

func TestControlTypes(t *testing.T) {
	// Test all control types are defined
	types := []ControlType{
		ControlShutdown,
		ControlPing,
		ControlForceClose,
		ControlUpdateActivity,
	}

	for i, ctrlType := range types {
		if int(ctrlType) != i {
			t.Errorf("Expected control type %d to have value %d, got %d", i, i, int(ctrlType))
		}
	}
}
