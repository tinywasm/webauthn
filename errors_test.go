//go:build wasm

package webauthn

import (
	"syscall/js"
	"testing"
)

func TestErrorStrings(t *testing.T) {
	tests := []struct {
		err      Error
		expected string
	}{
		{ErrUnavailable, "webauthn: not available in this browser"},
		{ErrAborted, "webauthn: ceremony cancelled by the user"},
		{ErrPRFUnsupported, "webauthn: authenticator does not support the prf extension"},
		{ErrNoCredential, "webauthn: no credential returned"},
		{ErrBadChallenge, "webauthn: challenge must be at least 16 bytes"},
	}

	for _, tc := range tests {
		if tc.err.Error() != tc.expected {
			t.Fatalf("got %q, want %q", tc.err.Error(), tc.expected)
		}
	}
}

func TestMapJSError(t *testing.T) {
	t.Run("NotAllowedError", func(t *testing.T) {
		jsErr := js.Global().Get("Object").New()
		jsErr.Set("name", "NotAllowedError")
		jsErr.Set("message", "User denied approval")

		err := mapJSError(jsErr)
		if err != ErrAborted {
			t.Fatalf("expected ErrAborted, got %v", err)
		}
	})

	t.Run("AbortError", func(t *testing.T) {
		jsErr := js.Global().Get("Object").New()
		jsErr.Set("name", "AbortError")
		jsErr.Set("message", "Operation aborted")

		err := mapJSError(jsErr)
		if err != ErrAborted {
			t.Fatalf("expected ErrAborted, got %v", err)
		}
	})

	t.Run("Other DOMException", func(t *testing.T) {
		jsErr := js.Global().Get("Object").New()
		jsErr.Set("name", "SecurityError")
		jsErr.Set("message", "Relying party ID is invalid")

		err := mapJSError(jsErr)
		expected := "webauthn: SecurityError: Relying party ID is invalid"
		if err == nil || err.Error() != expected {
			t.Fatalf("got %v, want %q", err, expected)
		}
	})

	t.Run("MapAwaitError substring", func(t *testing.T) {
		err := mapAwaitError(Error("NotAllowedError: user cancelled"))
		if err != ErrAborted {
			t.Fatalf("expected ErrAborted, got %v", err)
		}
	})
}
