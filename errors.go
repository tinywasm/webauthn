//go:build wasm

package webauthn

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
