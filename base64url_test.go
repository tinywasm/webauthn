//go:build wasm

package webauthn

import (
	"bytes"
	"testing"
)

func TestBase64URLRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty",
			input:    []byte(""),
			expected: "",
		},
		{
			name:     "length 1 mod 3",
			input:    []byte("f"),
			expected: "Zg",
		},
		{
			name:     "length 2 mod 3",
			input:    []byte("fo"),
			expected: "Zm8",
		},
		{
			name:     "length 0 mod 3 (3 bytes)",
			input:    []byte("foo"),
			expected: "Zm9v",
		},
		{
			name:     "4 bytes",
			input:    []byte("foob"),
			expected: "Zm9vYg",
		},
		{
			name:     "5 bytes",
			input:    []byte("fooba"),
			expected: "Zm9vYmE",
		},
		{
			name:     "6 bytes",
			input:    []byte("foobar"),
			expected: "Zm9vYmFy",
		},
		{
			name:     "url safe chars (-_)",
			input:    []byte{0xff, 0xef, 0xfe, 0x3e, 0xfa, 0x01},
			expected: "_-_-PvoB",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := base64URLEncode(tc.input)
			if encoded != tc.expected {
				t.Fatalf("encode got %q, want %q", encoded, tc.expected)
			}

			decoded := base64URLDecode(encoded)
			if !bytes.Equal(decoded, tc.input) {
				t.Fatalf("decode got %v, want %v", decoded, tc.input)
			}
		})
	}
}

func TestBase64URLDecodePadding(t *testing.T) {
	// Padding '=' should be stripped and decoded properly
	encodedWithPad := "Zg=="
	decoded := base64URLDecode(encodedWithPad)
	if string(decoded) != "f" {
		t.Fatalf("got %q, want %q", string(decoded), "f")
	}
}

func TestBase64URLDecodeInvalidChar(t *testing.T) {
	invalidStr := "Zg!$"
	decoded := base64URLDecode(invalidStr)
	if decoded != nil {
		t.Fatalf("expected nil for invalid chars, got %v", decoded)
	}
}
