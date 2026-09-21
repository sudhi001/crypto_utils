# crypto_utils (Go)

Encrypt, sign and exchange data between a Go backend and Flutter (Dart) or
Rust clients — with one wire format that all three understand.

This package is the **server-side** half of the toolkit:

| Implementation | Repository |
|---|---|
| Go (this package) | `crypto_utils` |
| Dart / Flutter | [`flutter_crypto_security`](https://github.com/sudhi001/flutter_crypto_security) |
| Rust | `crypto_utils_rust` |

All three are cross-tested against each other (216 checks in `interop/run.sh`)
and against a real envelope captured from production.

## What it does, in plain English

Think of sending a valuable letter:

1. The letter goes in a **steel box locked with a fresh padlock key** — that is
   AES-256-GCM, fast and tamper-evident.
2. The padlock key is far too sensitive to mail in the open, so it is snapped
   into a **tiny box that only the recipient can open** — RSA with the
   recipient's public key.
3. You press your **wax seal** on the parcel so the recipient knows it really
   came from you — an RSA signature.
4. Everything ships as one small JSON **envelope**:

```json
{ "payload": "…locked box…", "key": "…tiny box…", "nonce": "…fresh-start number…", "signature": "…wax seal…" }
```

`EncryptPayload` builds that parcel; `DecryptPayload` opens it. Everything
else in the package is the individual tools those two use. A longer
explanation with a glossary lives in `interop/PLAIN_ENGLISH.md`.

## Installation

```bash
go get github.com/sudhi001/crypto_utils
```

Requires Go 1.26+ (standard library only, no third-party dependencies).

## Quick start

```go
import "github.com/sudhi001/crypto_utils"

c := crypto_utils.NewCryptoUtils()

// 1. Keys — generated once, stored as plain strings (base64 of PEM).
serverPriv, serverPub, err := c.GenerateRSAKeyPair()

// 2. Open a request from the app.
var env crypto_utils.Envelope
_ = json.NewDecoder(r.Body).Decode(&env)             // {"payload","key","nonce"[,"signature"]}
plaintext, err := c.DecryptPayload(serverPriv, &env)  // or DecryptPayloadVerified(serverPriv, devicePub, &env)

// 3. Answer the app.
reply, err := c.EncryptPayloadSigned(devicePub, serverPriv, responseJSON)
_ = json.NewEncoder(w).Encode(reply)
```

Typed variants: `EncryptJSON(pub, v)` / `DecryptJSON(priv, &env, &v)`.
`*OAEP` variants wrap the AES key with RSA-OAEP-SHA256 instead of PKCS#1 v1.5.

### Reusing parsed keys

The string functions parse base64 + PEM on every call (~13% of an envelope
operation). In a server, parse once at start-up and use the `*WithKey(s)`
variants:

```go
serverPriv, _ := c.Base64ToPrivateKey(serverPrivS)
devicePub, _ := c.Base64ToPublicKey(devicePubS)
plaintext, err := c.DecryptPayloadWithKeys(serverPriv, devicePub, &env, false) // sender nil = unverified
reply, err := c.EncryptPayloadWithKeys(devicePub, serverPriv, responseJSON, false) // signer nil = unsigned
```

### Envelope v2 — 10× faster (X25519 + Ed25519)

RSA costs ~1.3 ms per private-key operation. The v2 envelope uses X25519 key
agreement, HKDF-SHA256, AES-256-GCM and an Ed25519 signature: ~0.14 ms per
message, 32-byte keys, same JSON style. Both formats are supported by all
three libraries; pick by the `"v": 2` field.

```go
xPriv, xPub, _ := c.GenerateX25519KeyPair()   // encryption key pair (base64 raw 32 bytes)
edPriv, edPub, _ := c.GenerateEd25519KeyPair() // signing key pair

env, err := c.EncryptPayloadV2(deviceXPub, serverEdPriv, payload) // sender "" = unsigned
plaintext, err := c.DecryptPayloadV2(serverXPriv, deviceEdPub, &env) // sender "" = unverified
// parsed-key variants: EncryptPayloadV2WithKeys / DecryptPayloadV2WithKeys
```

### Individual tools

```go
// RSA
ct, err := c.EncryptRSA(pub, small)                    // PKCS#1 v1.5 → base64
pt, err := c.DecryptWithPrivateKey(priv, ct)
ct, err  = c.EncryptWithPublicKeyOAEP(pub, small)      // OAEP-SHA256
pt, err  = c.DecryptWithPrivateKeyOAEP(priv, ct)

// AES-256-GCM
key, _ := c.GenerateRandomBytes(crypto_utils.AESKeySize)
ctB64, nonceB64, err := c.EncryptAESGCM(key, data)
data, err = c.DecryptAESGCM(key, ctB64, nonceB64)

// Signatures
sig, err := c.Sign(priv, message)                      // base64
ok, err := c.Verify(pub, message, sig)                 // (false, nil) = bad signature
```

## API reference

| Function | Description |
|---|---|
| `GenerateRSAKeyPair() (priv, pub string, err)` | RSA-2048 pair as base64(PEM) |
| `GenerateRandomBytes(n) ([]byte, error)` | CSPRNG bytes |
| `Base64ToPrivateKey / Base64ToPublicKey` | Parse base64(PEM) keys (PKCS#1/PKCS#8, PKIX/PKCS#1) |
| `EncryptRSA / DecryptWithPrivateKey` | RSA PKCS#1 v1.5, base64 ciphertext |
| `EncryptWithPublicKeyOAEP / DecryptWithPrivateKeyOAEP` | RSA-OAEP SHA-256 |
| `EncryptAESGCM / DecryptAESGCM` | AES-256-GCM with base64 in/out |
| `EncryptAESGCMWithNonce / DecryptAESGCMBytes` | AES-256-GCM on raw bytes |
| `Sign / Verify` | RSASSA-PKCS1-v1_5 SHA-256, base64 signature |
| `EncryptPayload[Signed][OAEP]` | Build an `Envelope` |
| `DecryptPayload[Verified][OAEP]` | Open an `Envelope` |
| `EncryptJSON / DecryptJSON` | Envelope + JSON marshalling |
| `EncryptRSAWithKey`, `DecryptRSAWithKey`, `SignWithKey`, `VerifyWithKey`, `EncryptPayloadWithKeys`, `DecryptPayloadWithKeys` | Same operations on already parsed keys |
| `GenerateX25519KeyPair`, `GenerateEd25519KeyPair` | v2 key pairs, base64 of raw 32 bytes |
| `SignEd25519 / VerifyEd25519` | Ed25519 signatures, base64 |
| `EncryptPayloadV2[WithKeys] / DecryptPayloadV2[WithKeys]` | Build / open an `EnvelopeV2` |
| `EncryptWithPublicKey`, `EncryptWithAES`, `DecryptWithAES`, `SignWithPrivateKey`, `VerifyWithPublicKey` | Legacy helpers (panic on error) |

Sentinel errors: `ErrInvalidKeyLength`, `ErrInvalidNonce`, `ErrMissingField`,
`ErrMissingSignature`, `ErrBadSignature`.

## Compatibility

* Envelopes from **older Flutter clients** (which wrapped the base64 *text* of
  the AES key) still open — `DecryptPayload` accepts both forms.
* JSON decoding is case-insensitive, so `Payload`/`Key`/`Nonce` also work.
* Wire format details: `interop/PROTOCOL.md`.

## Performance

Mean time per operation on Apple M4 (Darwin). Lower is better.
RSA rows include base64 + PEM parsing of the key on every call, as callers pay it;
the ↳ rows reuse a parsed key (Go `*WithKey`, Rust `PublicKey`/`PrivateKey`, Dart `Crypto` instance).
v2 rows are the X25519 + Ed25519 envelope; Dart runs it in pure Dart here — with the
`cryptography_flutter` plugin a Flutter app runs those primitives natively.

| Operation | Go | Rust (OpenSSL, default) | Rust (pure) | Dart (AOT) |
|---|---:|---:|---:|---:|
| RSA-2048 key pair generation | 81.19 ms | 51.03 ms | 253.42 ms | 191.61 ms |
| RSA encrypt, PKCS#1 v1.5 (32-byte AES key) | 45.1 µs | 36.3 µs | 174.7 µs | 185.0 µs |
| RSA decrypt, PKCS#1 v1.5 | 1.55 ms | 1.02 ms | 1.49 ms | 3.00 ms |
|   ↳ encrypt with pre-parsed key | 41.7 µs | 18.4 µs | 172.2 µs | 125.3 µs |
|   ↳ decrypt with pre-parsed key | 1.34 ms | 631.8 µs | 1.36 ms | 2.21 ms |
| RSA encrypt, OAEP-SHA256 | 46.0 µs | 38.0 µs | 177.5 µs | 218.9 µs |
| RSA decrypt, OAEP-SHA256 | 1.56 ms | 1.03 ms | 1.61 ms | 3.05 ms |
| AES-256-GCM encrypt, 1 KiB | 2.1 µs | 2.8 µs | 2.8 µs | 96.3 µs |
| AES-256-GCM decrypt, 1 KiB | 1.6 µs | 1.4 µs | 1.4 µs | 96.1 µs |
| AES-256-GCM encrypt, 1 MiB | 1.01 ms (1042 MB/s) | 843.4 µs (1243 MB/s) | 846.7 µs (1238 MB/s) | 91.65 ms (11 MB/s) |
| AES-256-GCM decrypt, 1 MiB | 938.2 µs (1118 MB/s) | 846.2 µs (1239 MB/s) | 847.2 µs (1238 MB/s) | 92.70 ms (11 MB/s) |
| Sign (RSA-SHA256), 1 KiB | 1.58 ms | 1.03 ms | 1.42 ms | 3.07 ms |
| Verify (RSA-SHA256), 1 KiB | 45.3 µs | 37.2 µs | 176.6 µs | 225.7 µs |
| Envelope encrypt + sign, 1 KiB | 1.63 ms | 1.07 ms | 1.59 ms | 3.35 ms |
| Envelope verify + decrypt, 1 KiB | 1.59 ms | 1.06 ms | 1.73 ms | 3.29 ms |
| **v2** X25519 + Ed25519 key pair generation | 63.1 µs | 33.0 µs | 32.8 µs | 1.93 ms |
| **v2** envelope encrypt + sign, 1 KiB | 136.7 µs | 99.3 µs | 92.8 µs | 5.19 ms |
| **v2** envelope verify + decrypt, 1 KiB | 140.7 µs | 104.1 µs | 98.3 µs | 4.06 ms |

Reproduce with `go test -bench . -benchmem -run '^$'` or, for all
implementations at once, `interop/bench.sh`.

## Testing

```bash
go test ./...          # unit tests, incl. the captured production envelope
../interop/run.sh      # cross-language interoperability suite
```

## License

MIT — see `LICENSE`.
