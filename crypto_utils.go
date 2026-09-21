// Package crypto_utils provides RSA + AES-GCM helpers that interoperate with the
// flutter_crypto_security (Dart) package and the crypto_utils Rust crate.
//
// Wire format shared by all implementations:
//
//   - Keys are RSA-2048 and transported as base64(PEM). Private keys use the
//     PKCS#1 "RSA PRIVATE KEY" form, public keys use the PKIX "PUBLIC KEY" form.
//   - RSA encryption uses PKCS#1 v1.5 padding by default; RSA-OAEP with SHA-256
//     (MGF1-SHA256, empty label) is available via the *OAEP functions.
//   - Symmetric encryption is AES-256-GCM with a 12-byte nonce and a 128-bit tag
//     appended to the ciphertext. No additional authenticated data is used.
//   - Signatures are RSASSA-PKCS1-v1_5 over the SHA-256 digest of the message.
//   - The hybrid Envelope carries base64 strings: "key" is the RSA-encrypted raw
//     32-byte AES key, "nonce" the GCM nonce, "payload" the GCM ciphertext and
//     "signature" (optional) a signature over the raw ciphertext bytes.
package crypto_utils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

const (
	// RSAKeyBits is the modulus size used by GenerateRSAKeyPair.
	RSAKeyBits = 2048
	// AESKeySize is the AES-256 key length in bytes.
	AESKeySize = 32
	// GCMNonceSize is the AES-GCM nonce length in bytes.
	GCMNonceSize = 12
)

var (
	ErrInvalidKeyLength = errors.New("crypto_utils: AES key must be 32 bytes")
	ErrInvalidNonce     = errors.New("crypto_utils: AES-GCM nonce must be 12 bytes")
	ErrMissingField     = errors.New("crypto_utils: envelope is missing key, nonce or payload")
	ErrBadSignature     = errors.New("crypto_utils: signature verification failed")
	ErrMissingSignature = errors.New("crypto_utils: envelope has no signature")
)

// Envelope is the hybrid-encryption container exchanged between client and server.
// JSON field names are lowercase; decoding is case-insensitive so the historical
// "Payload"/"Key"/"Nonce" spelling is also accepted.
type Envelope struct {
	Payload   string `json:"payload"`
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature,omitempty"`
}

// CryptoUtils groups the helpers; it holds no state.
type CryptoUtils struct{}

// NewCryptoUtils creates a new CryptoUtils.
func NewCryptoUtils() *CryptoUtils {
	return &CryptoUtils{}
}

// ---------------------------------------------------------------------------
// Random / keys
// ---------------------------------------------------------------------------

// GenerateRandomBytes returns size cryptographically secure random bytes.
func (c *CryptoUtils) GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	return bytes, err
}

// GenerateRSAKeyPair returns (privateKey, publicKey) as base64-encoded PEM strings.
func (c *CryptoUtils) GenerateRSAKeyPair() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		return "", "", err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return base64.StdEncoding.EncodeToString(privateKeyPEM), base64.StdEncoding.EncodeToString(publicKeyPEM), nil
}

// Base64ToPrivateKey converts a base64-encoded PEM string to an *rsa.PrivateKey.
// Both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") blocks are accepted.
func (c *CryptoUtils) Base64ToPrivateKey(base64PrivateKey string) (*rsa.PrivateKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 private key: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM block for private key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		return privateKey, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("parsed key is not an RSA private key")
		}
		return privateKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q for private key", block.Type)
	}
}

// Base64ToPublicKey converts a base64-encoded PEM string to an *rsa.PublicKey.
// Both PKIX ("PUBLIC KEY") and PKCS#1 ("RSA PUBLIC KEY") blocks are accepted.
func (c *CryptoUtils) Base64ToPublicKey(base64PublicKey string) (*rsa.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM block for public key")
	}

	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("parsed key is not an RSA public key")
		}
		return publicKey, nil
	case "RSA PUBLIC KEY":
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 public key: %w", err)
		}
		return publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q for public key", block.Type)
	}
}

// ---------------------------------------------------------------------------
// RSA encryption
// ---------------------------------------------------------------------------

// EncryptWithPublicKey encrypts message with RSA PKCS#1 v1.5 and returns base64.
// It panics on failure; prefer EncryptRSA for error handling.
func (c *CryptoUtils) EncryptWithPublicKey(publicKey *rsa.PublicKey, message []byte) string {
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes)
}

// EncryptRSA encrypts message with RSA PKCS#1 v1.5 using a base64 PEM public key.
func (c *CryptoUtils) EncryptRSA(publicKeyString string, message []byte) (string, error) {
	publicKey, err := c.Base64ToPublicKey(publicKeyString)
	if err != nil {
		return "", err
	}
	return c.EncryptRSAWithKey(publicKey, message, false)
}

// EncryptRSAWithKey is EncryptRSA / EncryptWithPublicKeyOAEP for an already
// parsed key. Parse keys once (Base64ToPublicKey) and reuse them in hot paths.
func (c *CryptoUtils) EncryptRSAWithKey(publicKey *rsa.PublicKey, message []byte, oaep bool) (string, error) {
	var encryptedBytes []byte
	var err error
	if oaep {
		encryptedBytes, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	} else {
		encryptedBytes, err = rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	}
	if err != nil {
		return "", fmt.Errorf("RSA encryption failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// DecryptRSAWithKey is DecryptWithPrivateKey / DecryptWithPrivateKeyOAEP for
// an already parsed key.
func (c *CryptoUtils) DecryptRSAWithKey(privateKey *rsa.PrivateKey, encryptedMessage string, oaep bool) ([]byte, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted message from base64: %w", err)
	}
	var decryptedBytes []byte
	if oaep {
		decryptedBytes, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedBytes, nil)
	} else {
		decryptedBytes, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed: %w", err)
	}
	return decryptedBytes, nil
}

// DecryptWithPrivateKey decrypts a base64 RSA PKCS#1 v1.5 ciphertext.
func (c *CryptoUtils) DecryptWithPrivateKey(privateKeyString string, encryptedMessage string) ([]byte, error) {
	privateKey, err := c.Base64ToPrivateKey(privateKeyString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from base64 string: %w", err)
	}
	return c.DecryptRSAWithKey(privateKey, encryptedMessage, false)
}

// DecryptRSA is an alias of DecryptWithPrivateKey, mirroring EncryptRSA.
func (c *CryptoUtils) DecryptRSA(privateKeyString string, encryptedMessage string) ([]byte, error) {
	return c.DecryptWithPrivateKey(privateKeyString, encryptedMessage)
}

// EncryptWithPublicKeyOAEP encrypts message with RSA-OAEP (SHA-256) and returns base64.
func (c *CryptoUtils) EncryptWithPublicKeyOAEP(publicKeyString string, message []byte) (string, error) {
	publicKey, err := c.Base64ToPublicKey(publicKeyString)
	if err != nil {
		return "", err
	}
	return c.EncryptRSAWithKey(publicKey, message, true)
}

// DecryptWithPrivateKeyOAEP decrypts a base64 RSA-OAEP (SHA-256) ciphertext.
func (c *CryptoUtils) DecryptWithPrivateKeyOAEP(privateKeyString string, encryptedMessage string) ([]byte, error) {
	privateKey, err := c.Base64ToPrivateKey(privateKeyString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from base64 string: %w", err)
	}
	return c.DecryptRSAWithKey(privateKey, encryptedMessage, true)
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

// EncryptAESGCM encrypts plaintext with AES-256-GCM using a fresh random nonce.
// It returns the base64 ciphertext (tag appended) and the base64 nonce.
func (c *CryptoUtils) EncryptAESGCM(key, plaintext []byte) (ciphertextB64 string, nonceB64 string, err error) {
	if len(key) != AESKeySize {
		return "", "", ErrInvalidKeyLength
	}
	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	ciphertext, err := c.EncryptAESGCMWithNonce(key, nonce, plaintext)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

// EncryptAESGCMWithNonce encrypts plaintext with AES-256-GCM using the supplied
// nonce and returns the raw ciphertext with the tag appended.
func (c *CryptoUtils) EncryptAESGCMWithNonce(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeyLength
	}
	if len(nonce) != GCMNonceSize {
		return nil, ErrInvalidNonce
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGCM.Seal(nil, nonce, plaintext, nil), nil
}

// DecryptAESGCM decrypts a base64 AES-256-GCM ciphertext with a base64 nonce.
func (c *CryptoUtils) DecryptAESGCM(key []byte, ciphertextB64, nonceB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext from base64: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce from base64: %w", err)
	}
	return c.DecryptAESGCMBytes(key, nonce, ciphertext)
}

// DecryptAESGCMBytes decrypts raw AES-256-GCM ciphertext (tag appended).
func (c *CryptoUtils) DecryptAESGCMBytes(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeyLength
	}
	if len(nonce) != GCMNonceSize {
		return nil, ErrInvalidNonce
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}
	return plaintext, nil
}

// EncryptWithAES is the legacy AES-GCM helper: it returns the base64 ciphertext
// and the raw nonce, and panics on failure. Prefer EncryptAESGCM.
func (c *CryptoUtils) EncryptWithAES(key, plaintext []byte) (ciphertext string, nonce []byte) {
	nonce = make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	ciphertextBytes, err := c.EncryptAESGCMWithNonce(key, nonce, plaintext)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(ciphertextBytes), nonce
}

// DecryptWithAES is the legacy AES-GCM helper: ciphertext is the base64 string
// as bytes, nonce is raw. It panics on failure. Prefer DecryptAESGCM.
func (c *CryptoUtils) DecryptWithAES(key, ciphertext, nonce []byte) string {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		panic(err)
	}
	plaintext, err := c.DecryptAESGCMBytes(key, nonce, ciphertextBytes)
	if err != nil {
		panic(err)
	}
	return string(plaintext)
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

// Sign returns the base64 RSASSA-PKCS1-v1_5/SHA-256 signature of message.
func (c *CryptoUtils) Sign(privateKeyString string, message []byte) (string, error) {
	privateKey, err := c.Base64ToPrivateKey(privateKeyString)
	if err != nil {
		return "", err
	}
	return c.SignWithKey(privateKey, message)
}

// SignWithKey is Sign for an already parsed key.
func (c *CryptoUtils) SignWithKey(privateKey *rsa.PrivateKey, message []byte) (string, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("RSA signing failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify checks a base64 RSASSA-PKCS1-v1_5/SHA-256 signature. It returns
// (false, nil) for a well-formed but invalid signature and a non-nil error
// when the key or signature cannot be decoded.
func (c *CryptoUtils) Verify(publicKeyString string, message []byte, base64Signature string) (bool, error) {
	publicKey, err := c.Base64ToPublicKey(publicKeyString)
	if err != nil {
		return false, err
	}
	return c.VerifyWithKey(publicKey, message, base64Signature)
}

// VerifyWithKey is Verify for an already parsed key.
func (c *CryptoUtils) VerifyWithKey(publicKey *rsa.PublicKey, message []byte, base64Signature string) (bool, error) {
	signature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature from base64: %w", err)
	}
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature) == nil, nil
}

// SignWithPrivateKey is the legacy signing helper; it panics on failure. Prefer Sign.
func (c *CryptoUtils) SignWithPrivateKey(privateKeyString string, message []byte) string {
	signature, err := c.Sign(privateKeyString, message)
	if err != nil {
		panic(err)
	}
	return signature
}

// VerifyWithPublicKey is the legacy verification helper; it panics if the key
// or signature cannot be decoded. Prefer Verify.
func (c *CryptoUtils) VerifyWithPublicKey(publicKeyString string, message []byte, base64Signature string) bool {
	ok, err := c.Verify(publicKeyString, message, base64Signature)
	if err != nil {
		panic(err)
	}
	return ok
}

// ---------------------------------------------------------------------------
// Hybrid envelope
// ---------------------------------------------------------------------------

// EncryptPayload wraps payload in an Envelope: a fresh AES-256 key encrypts the
// payload with GCM and the raw key is RSA PKCS#1 v1.5 encrypted for recipientPublicKey.
func (c *CryptoUtils) EncryptPayload(recipientPublicKey string, payload []byte) (*Envelope, error) {
	return c.encryptPayload(recipientPublicKey, "", payload, false)
}

// EncryptPayloadOAEP is EncryptPayload with RSA-OAEP (SHA-256) for the key.
func (c *CryptoUtils) EncryptPayloadOAEP(recipientPublicKey string, payload []byte) (*Envelope, error) {
	return c.encryptPayload(recipientPublicKey, "", payload, true)
}

// EncryptPayloadSigned is EncryptPayload plus a signature over the raw AES-GCM
// ciphertext made with senderPrivateKey.
func (c *CryptoUtils) EncryptPayloadSigned(recipientPublicKey, senderPrivateKey string, payload []byte) (*Envelope, error) {
	return c.encryptPayload(recipientPublicKey, senderPrivateKey, payload, false)
}

// EncryptPayloadSignedOAEP is EncryptPayloadSigned with RSA-OAEP (SHA-256) for the key.
func (c *CryptoUtils) EncryptPayloadSignedOAEP(recipientPublicKey, senderPrivateKey string, payload []byte) (*Envelope, error) {
	return c.encryptPayload(recipientPublicKey, senderPrivateKey, payload, true)
}

func (c *CryptoUtils) encryptPayload(recipientPublicKey, senderPrivateKey string, payload []byte, oaep bool) (*Envelope, error) {
	recipient, err := c.Base64ToPublicKey(recipientPublicKey)
	if err != nil {
		return nil, err
	}
	var signer *rsa.PrivateKey
	if senderPrivateKey != "" {
		if signer, err = c.Base64ToPrivateKey(senderPrivateKey); err != nil {
			return nil, err
		}
	}
	return c.EncryptPayloadWithKeys(recipient, signer, payload, oaep)
}

// EncryptPayloadWithKeys builds an Envelope for already parsed keys: the AES
// key is wrapped for recipient (PKCS#1 v1.5, or OAEP when oaep is true) and,
// when signer is non-nil, the ciphertext is signed. Parse keys once and reuse
// them in hot paths; parsing costs about 13% of an envelope operation.
func (c *CryptoUtils) EncryptPayloadWithKeys(recipient *rsa.PublicKey, signer *rsa.PrivateKey, payload []byte, oaep bool) (*Envelope, error) {
	aesKey, err := c.GenerateRandomBytes(AESKeySize)
	if err != nil {
		return nil, err
	}
	nonce, err := c.GenerateRandomBytes(GCMNonceSize)
	if err != nil {
		return nil, err
	}
	ciphertext, err := c.EncryptAESGCMWithNonce(aesKey, nonce, payload)
	if err != nil {
		return nil, err
	}
	encryptedKey, err := c.EncryptRSAWithKey(recipient, aesKey, oaep)
	if err != nil {
		return nil, err
	}

	env := &Envelope{
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Key:     encryptedKey,
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
	}
	if signer != nil {
		if env.Signature, err = c.SignWithKey(signer, ciphertext); err != nil {
			return nil, err
		}
	}
	return env, nil
}

// DecryptPayload opens an Envelope with recipientPrivateKey (RSA PKCS#1 v1.5).
// The signature, if present, is not checked; use DecryptPayloadVerified for that.
func (c *CryptoUtils) DecryptPayload(recipientPrivateKey string, env *Envelope) ([]byte, error) {
	return c.decryptPayload(recipientPrivateKey, "", env, false)
}

// DecryptPayloadOAEP is DecryptPayload for envelopes produced with RSA-OAEP.
func (c *CryptoUtils) DecryptPayloadOAEP(recipientPrivateKey string, env *Envelope) ([]byte, error) {
	return c.decryptPayload(recipientPrivateKey, "", env, true)
}

// DecryptPayloadVerified opens an Envelope and requires a valid signature from
// senderPublicKey over the raw ciphertext.
func (c *CryptoUtils) DecryptPayloadVerified(recipientPrivateKey, senderPublicKey string, env *Envelope) ([]byte, error) {
	return c.decryptPayload(recipientPrivateKey, senderPublicKey, env, false)
}

// DecryptPayloadVerifiedOAEP is DecryptPayloadVerified for RSA-OAEP envelopes.
func (c *CryptoUtils) DecryptPayloadVerifiedOAEP(recipientPrivateKey, senderPublicKey string, env *Envelope) ([]byte, error) {
	return c.decryptPayload(recipientPrivateKey, senderPublicKey, env, true)
}

func (c *CryptoUtils) decryptPayload(recipientPrivateKey, senderPublicKey string, env *Envelope, oaep bool) ([]byte, error) {
	if env == nil || env.Key == "" || env.Nonce == "" || env.Payload == "" {
		return nil, ErrMissingField
	}
	recipient, err := c.Base64ToPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	var sender *rsa.PublicKey
	if senderPublicKey != "" {
		if sender, err = c.Base64ToPublicKey(senderPublicKey); err != nil {
			return nil, err
		}
	}
	return c.DecryptPayloadWithKeys(recipient, sender, env, oaep)
}

// DecryptPayloadWithKeys opens an Envelope with already parsed keys. When
// sender is non-nil the envelope must carry a valid signature from it. Set
// oaep for envelopes whose key was wrapped with RSA-OAEP.
func (c *CryptoUtils) DecryptPayloadWithKeys(recipient *rsa.PrivateKey, sender *rsa.PublicKey, env *Envelope, oaep bool) ([]byte, error) {
	if env == nil || env.Key == "" || env.Nonce == "" || env.Payload == "" {
		return nil, ErrMissingField
	}

	ciphertext, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload from base64: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce from base64: %w", err)
	}

	if sender != nil {
		if env.Signature == "" {
			return nil, ErrMissingSignature
		}
		ok, err := c.VerifyWithKey(sender, ciphertext, env.Signature)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrBadSignature
		}
	}

	rawKey, err := c.DecryptRSAWithKey(recipient, env.Key, oaep)
	if err != nil {
		return nil, err
	}
	aesKey, err := normalizeAESKey(rawKey)
	if err != nil {
		return nil, err
	}
	return c.DecryptAESGCMBytes(aesKey, nonce, ciphertext)
}

// normalizeAESKey accepts the canonical raw 32-byte key and, for backward
// compatibility with older clients, the 44-character base64 text of the key.
func normalizeAESKey(raw []byte) ([]byte, error) {
	if len(raw) == AESKeySize {
		return raw, nil
	}
	if len(raw) == 44 {
		decoded, err := base64.StdEncoding.DecodeString(string(raw))
		if err == nil && len(decoded) == AESKeySize {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("crypto_utils: decrypted AES key has unexpected length %d", len(raw))
}

// EncryptJSON marshals v to JSON and wraps it with EncryptPayload.
func (c *CryptoUtils) EncryptJSON(recipientPublicKey string, v any) (*Envelope, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return c.EncryptPayload(recipientPublicKey, data)
}

// DecryptJSON opens an Envelope with DecryptPayload and unmarshals the JSON into v.
func (c *CryptoUtils) DecryptJSON(recipientPrivateKey string, env *Envelope, v any) error {
	data, err := c.DecryptPayload(recipientPrivateKey, env)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
