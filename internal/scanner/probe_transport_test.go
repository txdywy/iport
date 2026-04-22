package scanner

import (
	"bytes"
	"testing"
)

func TestWebSocketFrameRoundTripExtendedPayloads(t *testing.T) {
	tests := []int{125, 126, 65536}
	for _, size := range tests {
		payload := bytes.Repeat([]byte{0x5a}, size)
		got := extractWSPayload(makeWSFrame(payload))
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload size %d round trip mismatch: got %d bytes", size, len(got))
		}
	}
}

func TestExtractWSPayloadRejectsTruncatedExtendedLength(t *testing.T) {
	if got := extractWSPayload([]byte{0x82, 126}); got != nil {
		t.Fatalf("expected nil for truncated 16-bit length, got %d bytes", len(got))
	}
	if got := extractWSPayload([]byte{0x82, 127, 0, 0, 0}); got != nil {
		t.Fatalf("expected nil for truncated 64-bit length, got %d bytes", len(got))
	}
}
