---
PLAN: "feat: WebAuthn passkey ceremonies for the browser, with PRF support"
TAG: v0.1.0
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 10809142086678699384
PR: https://github.com/tinywasm/webauthn/pull/1
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.
>
> **Prerequisite: `github.com/tinywasm/await` must be released before this
> module is dispatched** — §3 and §"Why the API is synchronous" depend on it.
> If it is not yet on a tag, wait rather than inlining a copy of the pattern.

# Plan — `tinywasm/webauthn`, passkey ceremonies in WASM

## 1. Why this module exists

Two unrelated consumers need the same browser calls:

| Consumer | What it needs the passkey for |
|---|---|
| `tinywasm/keyring` | **Encryption.** The PRF extension yields deterministic key material that unlocks locally stored secrets. No server involved. |
| `tinywasm/user` | **Authentication.** A registration/assertion ceremony whose signature the edge verifies against a stored public key. |

Both call `navigator.credentials.create` / `.get` and serialise the same
`PublicKeyCredential` response. Neither should own that code. This module owns
it, and owns nothing else.

**Scope for v0.1.0 — client side only.** Server-side verification (CBOR
decoding of attestation objects, COSE key parsing, signature validation) is
deliberately excluded and will be planned separately once `tinywasm/user`
actually needs it. Building it now would be speculation.

## 2. The protocol fact that shapes this module

A passkey's private key never leaves the authenticator, and JS can only ask it to
**sign a challenge**. The obvious idea — derive an encryption key from that
signature — **does not work**: the signature covers `authenticatorData` (whose
`signCount` changes on every use) and the `clientDataHash` (whose challenge is
random). Every ceremony produces a different signature. Any design that derives
a key from an assertion signature is broken, and the executor must not
"optimise" toward one.

The correct primitive is the **PRF extension**, built on CTAP2's `hmac-secret`.
Given a fixed salt, the authenticator returns **32 deterministic bytes**,
released only after user verification (biometric or PIN). That output is key
material.

Two consequences that must be visible in this module's API:

- **PRF is not universally available.** Synced providers (Apple Passwords,
  Google Password Manager) support it reliably and Windows Hello returns PRF
  values as of the February 2026 update, but Safari on iOS does not pass
  extension data to external roaming authenticators — a YubiKey there yields
  nothing. `PRFSupported()` must be a first-class, checkable answer, never an
  assumption.
- **PRF output is not recoverable.** Lose the authenticator, lose the bytes.
  This module therefore never presents PRF as *the* key — that layering decision
  belongs to `keyring`, which wraps a data key with it.

## 3. Ecosystem rules that apply here

- **This module compiles to WASM.** Every file is `//go:build wasm`. This is
  precisely the code where the size rules bite:
  - **No stdlib `fmt`, `errors`, `strings`, `strconv`, `encoding/*`.**
  - Errors are a comparable string type declared locally (§5). Importing
    `tinywasm/fmt` to declare one error cost `tinywasm/base64` 74 KB; do not
    repeat that.
  - `syscall/js` and `github.com/tinywasm/await` are the only imports — see §4.
- Base64url encoding/decoding is needed. **Use `github.com/tinywasm/base64`** —
  its `URLEncode`/`URLDecode` are exactly this (RFC 4648 §5, unpadded, `-_`
  alphabet, strict decoder) and that module has **zero dependencies**, so it
  costs only the code you call. Do **not** use `encoding/base64`, and do **not**
  write your own: `tinywasm/jwt` already consumes `base64.URLEncode` for the
  same job, so a local copy here would be the ecosystem's third implementation
  of one alphabet.

**Prerequisite: `github.com/tinywasm/await` must be released before this
module starts.** It blocks a goroutine on a JS `Promise` — exactly what
`Create`/`Get` need for `navigator.credentials.create/get` — and is itself
zero-dependency (`syscall/js` only), built at
`https://github.com/tinywasm/await/blob/main/docs/PLAN.md` for precisely this
kind of consumer. If it is not available, stop and report; do not inline a
copy of the pattern.

## 4. Public API — implement exactly this surface

```go
package webauthn

// Available reports whether the browser exposes the WebAuthn API at all.
func Available() bool

// PlatformAuthenticatorAvailable blocks until the browser answers whether a
// built-in authenticator (Touch ID, Windows Hello, Android biometrics) exists.
func PlatformAuthenticatorAvailable() bool

// CreateOptions describes a registration ceremony.
type CreateOptions struct {
    RPID           string // relying party id — the origin's domain, e.g. "app.example.com"
    RPName         string
    UserID         []byte // opaque, stable, never the email
    UserName       string // shown in the account picker
    UserDisplayName string
    Challenge      []byte // 32 random bytes; server-issued for auth, local for encryption
    ResidentKey    bool   // true for a discoverable passkey
    UserVerification string // "required" | "preferred" | "discouraged"
    EnablePRF      bool   // request the prf extension
}

// Credential is the result of a registration ceremony.
type Credential struct {
    ID                []byte
    RawResponse       string // base64url JSON, ready to POST to a verifier
    PRFEnabled        bool   // the authenticator will honour prf on later assertions
}

// Create runs navigator.credentials.create. It blocks the calling goroutine
// until the user completes or cancels the ceremony, and MUST be called from a
// goroutine started by a user-gesture event handler.
func Create(opts CreateOptions) (*Credential, error)

// GetOptions describes an assertion ceremony.
type GetOptions struct {
    RPID             string
    Challenge        []byte
    AllowCredentials [][]byte // empty means "any discoverable credential"
    UserVerification string
    PRFSalt          []byte   // non-nil requests prf evaluation with this salt
}

// Assertion is the result of an assertion ceremony.
type Assertion struct {
    CredentialID []byte
    RawResponse  string // base64url JSON, ready to POST to a verifier
    PRFOutput    []byte // 32 bytes, or nil when prf was not requested or not supported
}

// Get runs navigator.credentials.get. Same goroutine and gesture requirements
// as Create.
func Get(opts GetOptions) (*Assertion, error)
```

### Why the API is synchronous

WebAuthn is promise-based, but every consumer is easier to write against
blocking calls. Block the goroutine on the promise with
`await.Promise(p)` from `github.com/tinywasm/await` — **import it, do not
copy it**. An earlier draft of this plan called for pasting the ~35-line
pattern inline to avoid a dependency; that was the wrong call once the
pattern was about to be duplicated a fourth and fifth time across this module,
`keyring/browser`, `jsvalue` and `indexdb`. `tinywasm/await` exists precisely
so none of them has to choose between a dependency and a copy — it is
`syscall/js`-only, so importing it costs exactly what `Promise` costs, nothing
more.

**Document the gesture rule prominently in the README**: calling `Create` or
`Get` from the WASM main goroutine deadlocks the JS event loop, and calling it
outside a user gesture makes the browser reject the ceremony. Both are caller
errors that no amount of library code can fix, so they must be impossible to
miss.

## 5. Errors

```go
type Error string
func (e Error) Error() string { return string(e) }

const (
    ErrUnavailable    Error = "webauthn: not available in this browser"
    ErrAborted        Error = "webauthn: ceremony cancelled by the user"
    ErrPRFUnsupported Error = "webauthn: authenticator does not support the prf extension"
    ErrNoCredential   Error = "webauthn: no credential returned"
    ErrBadChallenge   Error = "webauthn: challenge must be at least 16 bytes"
)
```

`ErrAborted` is not a failure to log loudly — the user pressing Cancel is a
normal outcome. Map JS `NotAllowedError` and `AbortError` onto it; every other
`DOMException` becomes `Error("webauthn: " + name + ": " + message)`.

## 6. PRF mechanics — the part that must be exact

Request during registration:

```js
publicKey.extensions = { prf: {} }
```

Then read `credential.getClientExtensionResults().prf` — if `enabled === true`,
later assertions can evaluate the PRF. Some authenticators report `enabled` only
at creation time and cannot evaluate at creation; **never assume PRF output is
available from `Create`**, only that it is `enabled`.

Request during assertion:

```js
publicKey.extensions = { prf: { eval: { first: <salt bytes> } } }
```

Read `getClientExtensionResults().prf.results.first` — an `ArrayBuffer` of 32
bytes. If `prf` or `prf.results` is absent, return `ErrPRFUnsupported`; do not
fabricate, pad, or fall back to any other value. A silent fallback here would
encrypt data under a key that cannot be reproduced.

The salt is supplied by the caller and must be a fixed, application-specific
constant. State in the README that **changing the salt changes the derived key**
and orphans everything encrypted under the old one.

## 7. Files to create

| File | Contents |
|---|---|
| `webauthn.go` | `Available`, `PlatformAuthenticatorAvailable`, shared JS helpers |
| `create.go` | `CreateOptions`, `Credential`, `Create` |
| `get.go` | `GetOptions`, `Assertion`, `Get` |
| `prf.go` | building the `prf` extension object and reading its results |
| `errors.go` | §5 |
| `tests/` | see §8 |

**Two files this module must NOT contain**, because each would duplicate a
zero-dependency module that already exists:

- no `base64url.go` — use `github.com/tinywasm/base64` (§3)
- no `await.go` — `Create`/`Get` block via `await.Promise` from
  `github.com/tinywasm/await`

If either module is unavailable when you start, **stop and report it**. Do not
vendor it, do not add a `replace` directive pointing at a local copy, and do
not inline the implementation to keep going — a local stand-in silently becomes
the ecosystem's second implementation, which is the exact outcome both modules
exist to prevent.

All files carry `//go:build wasm`.

## 8. Tests

WebAuthn cannot be exercised headlessly without a virtual authenticator, so the
test strategy is split honestly rather than pretending:

1. **Pure-Go units, no JS** — option validation (a 15-byte challenge yields
   `ErrBadChallenge`) and error mapping to the typed error. These run under
   `gotest` normally. Do **not** test base64url here: it belongs to
   `github.com/tinywasm/base64` and is covered there. Note that the error
   mapper receives a **flattened string**, not a `js.Value` — `await.Promise`
   already converted the rejection via the DOMException's `toString()`, which
   yields `"Name: message"` — so the mapper recovers `ErrAborted` by matching
   that string, and that is the only path worth testing.
2. **JS shape assertions** — build the `publicKey` options object from a
   `CreateOptions` and assert the resulting `js.Value` has the expected keys,
   types and nesting (`extensions.prf` present only when `EnablePRF` is set).
   These run under `gotest -tinygo` in the WASM harness with a stub
   `navigator.credentials` injected into `js.Global()`.
3. **Real-authenticator verification is manual.** Write
   `docs/MANUAL_VERIFICATION.md` listing the exact steps against Chrome DevTools'
   Virtual Authenticator (enable "supports PRF") and one real device, with the
   expected outcome per step. Do not fake this in CI and do not claim coverage
   the tests do not have.

## 9. Documentation to write

- `README.md` — what a passkey is, the "signatures are not deterministic"
  warning from §2, the gesture/goroutine rule, and both ceremonies in ~15 lines.
- `docs/PRF.md` — the encryption use case, current support matrix, and the
  irreversible-loss warning.
- `docs/ARCHITECTURE.md` — where this module stops (client only) and who owns
  verification.

## 10. Consumers

- `https://github.com/tinywasm/keyring/blob/main/docs/PLAN_STAGE_6_PASSKEY.md`
  — uses `Get` with `PRFSalt` to derive a key-encryption key. It is the only
  consumer at v0.1.0 and its stage 6 is blocked on this module.
- `tinywasm/user` will use `Create`/`Get` for login once the edge verifier is
  planned. Do not build for it speculatively.
