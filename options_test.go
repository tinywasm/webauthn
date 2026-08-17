//go:build wasm

package webauthn

import (
	"syscall/js"
	"testing"
)

func TestCreateOptionsValidation(t *testing.T) {
	opts := CreateOptions{
		Challenge: []byte("short"), // 5 bytes < 16 bytes
	}
	_, err := Create(opts)
	if err != ErrBadChallenge {
		t.Fatalf("expected ErrBadChallenge, got %v", err)
	}
}

func TestGetOptionsValidation(t *testing.T) {
	opts := GetOptions{
		Challenge: []byte("short"), // 5 bytes < 16 bytes
	}
	_, err := Get(opts)
	if err != ErrBadChallenge {
		t.Fatalf("expected ErrBadChallenge, got %v", err)
	}
}

func TestPRFExtensionBuilderAndParser(t *testing.T) {
	t.Run("Create PRF Extension", func(t *testing.T) {
		ext := buildCreatePRFExtension()
		prfObj := ext.Get("prf")
		if prfObj.IsUndefined() || prfObj.IsNull() {
			t.Fatal("expected prf key in extensions")
		}

		// Test parseCreatePRFResult
		extRes := js.Global().Get("Object").New()
		pRes := js.Global().Get("Object").New()
		pRes.Set("enabled", true)
		extRes.Set("prf", pRes)

		if !parseCreatePRFResult(extRes) {
			t.Fatal("expected parseCreatePRFResult to return true")
		}
	})

	t.Run("Get PRF Extension", func(t *testing.T) {
		salt := []byte("01234567890123456789012345678901") // 32 bytes
		ext := buildGetPRFExtension(salt)
		prfObj := ext.Get("prf")
		if prfObj.IsUndefined() || prfObj.IsNull() {
			t.Fatal("expected prf key in extensions")
		}
		evalObj := prfObj.Get("eval")
		if evalObj.IsUndefined() || evalObj.IsNull() {
			t.Fatal("expected eval key in prf")
		}
		firstAB := evalObj.Get("first")
		if firstAB.IsUndefined() || firstAB.IsNull() {
			t.Fatal("expected first ArrayBuffer in eval")
		}

		// Test parseGetPRFResult with valid PRF result
		extRes := js.Global().Get("Object").New()
		pRes := js.Global().Get("Object").New()
		resultsObj := js.Global().Get("Object").New()

		outputBytes := []byte("32byteslongsecretkeymaterial1234")
		resultsObj.Set("first", bytesToArrayBuffer(outputBytes))
		pRes.Set("results", resultsObj)
		extRes.Set("prf", pRes)

		resBytes, err := parseGetPRFResult(extRes)
		if err != nil {
			t.Fatalf("unexpected error parsing get PRF result: %v", err)
		}
		if string(resBytes) != string(outputBytes) {
			t.Fatalf("got %q, want %q", string(resBytes), string(outputBytes))
		}
	})

	t.Run("Get PRF Extension Unsupported", func(t *testing.T) {
		extRes := js.Global().Get("Object").New()
		// prf missing from extRes
		_, err := parseGetPRFResult(extRes)
		if err != ErrPRFUnsupported {
			t.Fatalf("expected ErrPRFUnsupported, got %v", err)
		}
	})
}
