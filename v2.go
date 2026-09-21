package crypto_utils

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Envelope v2 uses X25519 key agreement, HKDF-SHA256 and AES-256-GCM, with an
// optional Ed25519 signature. Private-key operations are ~30x faster than the
// RSA envelope. Keys are transported as base64 of their raw 32 bytes.
//
// See interop/PROTOCOL.md, "Envelope v2".

const (
	// EnvelopeV2Version is the value of EnvelopeV2.V.
	EnvelopeV2Version = 2
	// EnvelopeV2Info is the HKDF info prefix; the ephemeral and recipient
	// public keys are appended to it.
	EnvelopeV2Info = "crypto_utils/v2/x25519-aes256gcm"
	// CurveKeySize is the byte length of X25519 and Ed25519 public keys and seeds.
	CurveKeySize = 32
)

var (
	ErrInvalidCurveKey  = errors.New("crypto_utils: X25519/Ed25519 key must be 32 bytes")
	ErrUnsupportedVer   = errors.New("crypto_utils: unsupported envelope version")
	ErrWeakSharedSecret = errors.New("crypto_utils: X25519 produced an all-zero shared secret")
)

// EnvelopeV2 is the X25519 hybrid-encryption container.
type EnvelopeV2 struct {
	V         int    `json:"v"`
	EPK       string `json:"epk"`
	Nonce     string `json:"nonce"`
	Payload   string `json:"payload"`
	Signature string `json:"signature,omitempty"`
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// GenerateX25519KeyPair returns (privateKey, publicKey) as base64 of the raw 32 bytes.
func (c *CryptoUtils) GenerateX25519KeyPair() (string, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// GenerateEd25519KeyPair returns (privateSeed, publicKey) as base64 of the raw 32 bytes.
func (c *CryptoUtils) GenerateEd25519KeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()),
		base64.StdEncoding.EncodeToString(pub), nil
}

// Base64ToX25519PrivateKey parses a base64 raw X25519 private key.
func (c *CryptoUtils) Base64ToX25519PrivateKey(b64 string) (*ecdh.PrivateKey, error) {
	raw, err := decodeCurveKey(b64)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}
	return key, nil
}

// Base64ToX25519PublicKey parses a base64 raw X25519 public key.
func (c *CryptoUtils) Base64ToX25519PublicKey(b64 string) (*ecdh.PublicKey, error) {
	raw, err := decodeCurveKey(b64)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}
	return key, nil
}

// Base64ToEd25519PrivateKey parses a base64 32-byte Ed25519 seed.
func (c *CryptoUtils) Base64ToEd25519PrivateKey(b64 string) (ed25519.PrivateKey, error) {
	seed, err := decodeCurveKey(b64)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Base64ToEd25519PublicKey parses a base64 raw Ed25519 public key.
func (c *CryptoUtils) Base64ToEd25519PublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := decodeCurveKey(b64)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func decodeCurveKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key from base64: %w", err)
	}
	if len(raw) != CurveKeySize {
		return nil, ErrInvalidCurveKey
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// Ed25519 signatures
// ---------------------------------------------------------------------------

// SignEd25519 returns the base64 Ed25519 signature of message.
func (c *CryptoUtils) SignEd25519(privateSeedB64 string, message []byte) (string, error) {
	key, err := c.Base64ToEd25519PrivateKey(privateSeedB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, message)), nil
}

// VerifyEd25519 checks a base64 Ed25519 signature; (false, nil) means invalid.
func (c *CryptoUtils) VerifyEd25519(publicKeyB64 string, message []byte, signatureB64 string) (bool, error) {
	key, err := c.Base64ToEd25519PublicKey(publicKeyB64)
	if err != nil {
		return false, err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature from base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, nil
	}
	return ed25519.Verify(key, message, sig), nil
}

// ---------------------------------------------------------------------------
// Envelope v2
// ---------------------------------------------------------------------------

// EncryptPayloadV2 builds an EnvelopeV2 for recipientX25519PublicKey (base64
// raw). senderEd25519Seed (base64 raw) may be "" for an unsigned envelope.
func (c *CryptoUtils) EncryptPayloadV2(recipientX25519PublicKey, senderEd25519Seed string, payload []byte) (*EnvelopeV2, error) {
	recipient, err := c.Base64ToX25519PublicKey(recipientX25519PublicKey)
	if err != nil {
		return nil, err
	}
	var signer ed25519.PrivateKey
	if senderEd25519Seed != "" {
		if signer, err = c.Base64ToEd25519PrivateKey(senderEd25519Seed); err != nil {
			return nil, err
		}
	}
	return c.EncryptPayloadV2WithKeys(recipient, signer, payload)
}

// EncryptPayloadV2WithKeys is EncryptPayloadV2 for parsed keys; signer may be nil.
func (c *CryptoUtils) EncryptPayloadV2WithKeys(recipient *ecdh.PublicKey, signer ed25519.PrivateKey, payload []byte) (*EnvelopeV2, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	epk := ephemeral.PublicKey().Bytes()
	aesKey, err := deriveV2Key(ephemeral, recipient, epk, recipient.Bytes())
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

	env := &EnvelopeV2{
		V:       EnvelopeV2Version,
		EPK:     base64.StdEncoding.EncodeToString(epk),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
	}
	if signer != nil {
		env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, v2SignedData(epk, nonce, ciphertext)))
	}
	return env, nil
}

// DecryptPayloadV2 opens an EnvelopeV2 with recipientX25519PrivateKey (base64
// raw). When senderEd25519PublicKey is non-empty a valid signature is required.
func (c *CryptoUtils) DecryptPayloadV2(recipientX25519PrivateKey, senderEd25519PublicKey string, env *EnvelopeV2) ([]byte, error) {
	recipient, err := c.Base64ToX25519PrivateKey(recipientX25519PrivateKey)
	if err != nil {
		return nil, err
	}
	var sender ed25519.PublicKey
	if senderEd25519PublicKey != "" {
		if sender, err = c.Base64ToEd25519PublicKey(senderEd25519PublicKey); err != nil {
			return nil, err
		}
	}
	return c.DecryptPayloadV2WithKeys(recipient, sender, env)
}

// DecryptPayloadV2WithKeys is DecryptPayloadV2 for parsed keys; sender may be nil.
func (c *CryptoUtils) DecryptPayloadV2WithKeys(recipient *ecdh.PrivateKey, sender ed25519.PublicKey, env *EnvelopeV2) ([]byte, error) {
	if env == nil || env.EPK == "" || env.Nonce == "" || env.Payload == "" {
		return nil, ErrMissingField
	}
	if env.V != EnvelopeV2Version {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVer, env.V)
	}
	epk, err := decodeCurveKey(env.EPK)
	if err != nil {
		return nil, fmt.Errorf("epk: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce from base64: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload from base64: %w", err)
	}

	if sender != nil {
		if env.Signature == "" {
			return nil, ErrMissingSignature
		}
		sig, err := base64.StdEncoding.DecodeString(env.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature from base64: %w", err)
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(sender, v2SignedData(epk, nonce, ciphertext), sig) {
			return nil, ErrBadSignature
		}
	}

	ephemeral, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}
	aesKey, err := deriveV2Key(recipient, ephemeral, epk, recipient.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return c.DecryptAESGCMBytes(aesKey, nonce, ciphertext)
}

// deriveV2Key = HKDF-SHA256(X25519(priv, pub), salt="", info=EnvelopeV2Info||epk||recipientPK).
func deriveV2Key(priv *ecdh.PrivateKey, pub *ecdh.PublicKey, epk, recipientPK []byte) ([]byte, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("X25519 failed: %w", err)
	}
	allZero := true
	for _, b := range shared {
		allZero = allZero && b == 0
	}
	if allZero {
		return nil, ErrWeakSharedSecret
	}
	info := make([]byte, 0, len(EnvelopeV2Info)+2*CurveKeySize)
	info = append(info, EnvelopeV2Info...)
	info = append(info, epk...)
	info = append(info, recipientPK...)
	return hkdf.Key(sha256.New, shared, nil, string(info), AESKeySize)
}

// v2SignedData = epk || nonce || ciphertext.
func v2SignedData(epk, nonce, ciphertext []byte) []byte {
	out := make([]byte, 0, len(epk)+len(nonce)+len(ciphertext))
	out = append(out, epk...)
	out = append(out, nonce...)
	return append(out, ciphertext...)
}
