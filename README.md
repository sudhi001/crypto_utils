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
the ↳ rows reuse a parsed key object (Rust `PublicKey` / `PrivateKey`).

| Operation | Go | Rust (OpenSSL, default) | Rust (pure) | Dart (AOT) |
|---|---:|---:|---:|---:|
| RSA-2048 key pair generation | 83.92 ms | 40.48 ms | 200.22 ms | 205.45 ms |
| RSA encrypt, PKCS#1 v1.5 (32-byte AES key) | 45.0 µs | 36.3 µs | 173.9 µs | 185.3 µs |
| RSA decrypt, PKCS#1 v1.5 | 1.55 ms | 1.02 ms | 1.41 ms | 2.96 ms |
|   ↳ encrypt with pre-parsed key object | – | 18.4 µs | 170.6 µs | – |
|   ↳ decrypt with pre-parsed key object | – | 632.1 µs | 1.35 ms | – |
| RSA encrypt, OAEP-SHA256 | 46.0 µs | 38.1 µs | 175.8 µs | 212.4 µs |
| RSA decrypt, OAEP-SHA256 | 1.56 ms | 1.02 ms | 1.42 ms | 2.99 ms |
| AES-256-GCM encrypt, 1 KiB | 2.1 µs | 2.8 µs | 2.8 µs | 96.0 µs |
| AES-256-GCM decrypt, 1 KiB | 1.6 µs | 1.4 µs | 1.4 µs | 96.1 µs |
| AES-256-GCM encrypt, 1 MiB | 1.00 ms (1044 MB/s) | 839.6 µs (1249 MB/s) | 847.3 µs (1238 MB/s) | 91.40 ms (11 MB/s) |
| AES-256-GCM decrypt, 1 MiB | 944.2 µs (1111 MB/s) | 842.4 µs (1245 MB/s) | 849.9 µs (1234 MB/s) | 92.75 ms (11 MB/s) |
| Sign (RSA-SHA256), 1 KiB | 1.58 ms | 1.02 ms | 1.42 ms | 3.24 ms |
| Verify (RSA-SHA256), 1 KiB | 45.0 µs | 37.1 µs | 175.6 µs | 222.8 µs |
| Envelope encrypt + sign, 1 KiB | 1.62 ms | 1.06 ms | 1.59 ms | 3.32 ms |
| Envelope verify + decrypt, 1 KiB | 1.61 ms | 1.06 ms | 1.59 ms | 3.47 ms |

Reproduce with `go test -bench . -benchmem -run '^$'` or, for all
implementations at once, `interop/bench.sh`.

## Testing

```bash
go test ./...          # unit tests, incl. the captured production envelope
../interop/run.sh      # cross-language interoperability suite
```

## License

MIT — see `LICENSE`.
