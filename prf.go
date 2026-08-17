//go:build wasm

package webauthn

import "syscall/js"

// buildCreatePRFExtension constructs the publicKey.extensions object for registration
// when PRF is requested: { prf: {} }.
func buildCreatePRFExtension() js.Value {
	ext := js.Global().Get("Object").New()
	ext.Set("prf", js.Global().Get("Object").New())
	return ext
}

// buildGetPRFExtension constructs the publicKey.extensions object for assertion
// with the given salt: { prf: { eval: { first: <ArrayBuffer> } } }.
func buildGetPRFExtension(salt []byte) js.Value {
	ext := js.Global().Get("Object").New()
	prf := js.Global().Get("Object").New()
	evalObj := js.Global().Get("Object").New()

	evalObj.Set("first", bytesToArrayBuffer(salt))
	prf.Set("eval", evalObj)
	ext.Set("prf", prf)
	return ext
}

// parseCreatePRFResult checks if credential.getClientExtensionResults().prf.enabled is true.
func parseCreatePRFResult(extResults js.Value) bool {
	if extResults.IsUndefined() || extResults.IsNull() {
		return false
	}
	prf := extResults.Get("prf")
	if prf.IsUndefined() || prf.IsNull() {
		return false
	}
	enabled := prf.Get("enabled")
	if enabled.IsUndefined() || enabled.IsNull() {
		return false
	}
	return enabled.Bool()
}

// parseGetPRFResult extracts the 32-byte PRF output from
// credential.getClientExtensionResults().prf.results.first.
// Returns ErrPRFUnsupported if prf or prf.results or first is absent.
func parseGetPRFResult(extResults js.Value) ([]byte, error) {
	if extResults.IsUndefined() || extResults.IsNull() {
		return nil, ErrPRFUnsupported
	}
	prf := extResults.Get("prf")
	if prf.IsUndefined() || prf.IsNull() {
		return nil, ErrPRFUnsupported
	}
	results := prf.Get("results")
	if results.IsUndefined() || results.IsNull() {
		return nil, ErrPRFUnsupported
	}
	first := results.Get("first")
	if first.IsUndefined() || first.IsNull() {
		return nil, ErrPRFUnsupported
	}
	out := arrayBufferToBytes(first)
	if len(out) == 0 {
		return nil, ErrPRFUnsupported
	}
	return out, nil
}
