//go:build wasm

package webauthn

import "syscall/js"

// Error is a comparable string type representing WebAuthn errors.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrUnavailable    Error = "webauthn: not available in this browser"
	ErrAborted        Error = "webauthn: ceremony cancelled by the user"
	ErrPRFUnsupported Error = "webauthn: authenticator does not support the prf extension"
	ErrNoCredential   Error = "webauthn: no credential returned"
	ErrBadChallenge   Error = "webauthn: challenge must be at least 16 bytes"
)

// mapJSError converts a JavaScript error/exception js.Value into a Go error.
func mapJSError(jsErr js.Value) error {
	if jsErr.IsUndefined() || jsErr.IsNull() {
		return Error("webauthn: unknown error")
	}

	nameVal := jsErr.Get("name")
	var name string
	if !nameVal.IsUndefined() && !nameVal.IsNull() {
		name = nameVal.String()
	}

	if name == "NotAllowedError" || name == "AbortError" {
		return ErrAborted
	}

	msgVal := jsErr.Get("message")
	var message string
	if !msgVal.IsUndefined() && !msgVal.IsNull() {
		message = msgVal.String()
	}

	if name != "" && message != "" {
		return Error("webauthn: " + name + ": " + message)
	}
	if message != "" {
		return Error("webauthn: " + message)
	}
	if name != "" {
		return Error("webauthn: " + name)
	}

	return Error("webauthn: " + jsErr.String())
}
