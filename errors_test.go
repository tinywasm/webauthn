//go:build wasm

package webauthn

import (
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

// TestMapAwaitError covers the only error path that actually runs: await.Promise
// rejects with the DOMException's toString(), which is "Name: message", and
// mapAwaitError has to recover the typed error from that flattened string.
func TestMapAwaitError(t *testing.T) {
	t.Run("NotAllowedError", func(t *testing.T) {
		err := mapAwaitError(Error("NotAllowedError: User denied approval"))
		if err != ErrAborted {
			t.Fatalf("expected ErrAborted, got %v", err)
		}
	})

	t.Run("AbortError", func(t *testing.T) {
		err := mapAwaitError(Error("AbortError: Operation aborted"))
		if err != ErrAborted {
			t.Fatalf("expected ErrAborted, got %v", err)
		}
	})

	t.Run("Other DOMException is passed through", func(t *testing.T) {
		err := mapAwaitError(Error("SecurityError: Relying party ID is invalid"))
		expected := "webauthn: SecurityError: Relying party ID is invalid"
		if err == nil || err.Error() != expected {
			t.Fatalf("got %v, want %q", err, expected)
		}
	})

	t.Run("nil stays nil", func(t *testing.T) {
		if err := mapAwaitError(nil); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})
}
