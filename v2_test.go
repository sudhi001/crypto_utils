package crypto_utils_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sudhi001/crypto_utils"
)

func mustV2Keys(t *testing.T) (xPriv, xPub, edPriv, edPub string) {
	t.Helper()
	c := crypto_utils.NewCryptoUtils()
	var err error
	if xPriv, xPub, err = c.GenerateX25519KeyPair(); err != nil {
		t.Fatal(err)
	}
	if edPriv, edPub, err = c.GenerateEd25519KeyPair(); err != nil {
		t.Fatal(err)
	}
	return
}

func TestV2KeysAreRaw32Bytes(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	xPriv, xPub, edPriv, edPub := mustV2Keys(t)
	for _, k := range []string{xPriv, xPub, edPriv, edPub} {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != 32 {
			t.Fatalf("key is not base64 of 32 bytes: %q", k)
		}
	}
	if _, err := c.Base64ToX25519PrivateKey(xPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Base64ToX25519PublicKey(xPub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Base64ToEd25519PrivateKey(edPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Base64ToEd25519PublicKey(edPub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Base64ToX25519PublicKey(base64.StdEncoding.EncodeToString([]byte("short"))); !errors.Is(err, crypto_utils.ErrInvalidCurveKey) {
		t.Fatalf("expected ErrInvalidCurveKey, got %v", err)
	}
	// Ed25519 private key is the seed; its derived public key must match.
	priv, _ := c.Base64ToEd25519PrivateKey(edPriv)
	if base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) != edPub {
		t.Fatal("Ed25519 seed does not derive the published public key")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	_, _, edPriv, edPub := mustV2Keys(t)
	_, _, _, otherPub := mustV2Keys(t)
	msg := []byte("sign me")
	sig, err := c.SignEd25519(edPriv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(sig); len(raw) != 64 {
		t.Fatalf("signature length %d", len(raw))
	}
	if ok, err := c.VerifyEd25519(edPub, msg, sig); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := c.VerifyEd25519(edPub, []byte("sign me!"), sig); ok {
		t.Fatal("verified altered message")
	}
	if ok, _ := c.VerifyEd25519(otherPub, msg, sig); ok {
		t.Fatal("verified with wrong key")
	}
	if ok, err := c.VerifyEd25519(edPub, msg, "AAAA"); err != nil || ok {
		t.Fatalf("short signature should be (false, nil), got %v %v", ok, err)
	}
}

func TestEnvelopeV2RoundTrip(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	xPriv, xPub, _, _ := mustV2Keys(t)
	payload := []byte(`{"hello":"v2"}`)

	env, err := c.EncryptPayloadV2(xPub, "", payload)
	if err != nil {
		t.Fatal(err)
	}
	if env.V != 2 || env.Signature != "" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	data, _ := json.Marshal(env)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for _, k := range []string{"v", "epk", "nonce", "payload"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %q in %s", k, data)
		}
	}
	if _, ok := m["signature"]; ok {
		t.Errorf("unsigned envelope carries signature: %s", data)
	}

	got, err := c.DecryptPayloadV2(xPriv, "", env)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	// Every envelope uses a fresh ephemeral key.
	env2, _ := c.EncryptPayloadV2(xPub, "", payload)
	if env2.EPK == env.EPK {
		t.Fatal("ephemeral key reused")
	}
}

func TestEnvelopeV2SignedAndTampering(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	sPriv, sPub, _, _ := mustV2Keys(t)
	_, _, dPriv, dPub := mustV2Keys(t)
	_, _, _, strangerPub := mustV2Keys(t)
	oPriv, _, _, _ := mustV2Keys(t)
	payload := []byte("signed v2")

	env, err := c.EncryptPayloadV2(sPub, dPriv, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DecryptPayloadV2(sPriv, dPub, env)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("verified round trip: %q %v", got, err)
	}
	if _, err := c.DecryptPayloadV2(sPriv, strangerPub, env); !errors.Is(err, crypto_utils.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
	if _, err := c.DecryptPayloadV2(oPriv, dPub, env); err == nil {
		t.Fatal("wrong recipient key unexpectedly succeeded")
	}

	tamper := func(mutate func(e *crypto_utils.EnvelopeV2)) error {
		e := *env
		mutate(&e)
		_, err := c.DecryptPayloadV2(sPriv, dPub, &e)
		return err
	}
	flip := func(s string) string {
		raw, _ := base64.StdEncoding.DecodeString(s)
		raw[0] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	if err := tamper(func(e *crypto_utils.EnvelopeV2) { e.Payload = flip(e.Payload) }); !errors.Is(err, crypto_utils.ErrBadSignature) {
		t.Fatalf("payload tamper: %v", err)
	}
	if err := tamper(func(e *crypto_utils.EnvelopeV2) { e.Nonce = flip(e.Nonce) }); !errors.Is(err, crypto_utils.ErrBadSignature) {
		t.Fatalf("nonce tamper: %v", err)
	}
	if err := tamper(func(e *crypto_utils.EnvelopeV2) { e.EPK = flip(e.EPK) }); !errors.Is(err, crypto_utils.ErrBadSignature) {
		t.Fatalf("epk tamper: %v", err)
	}
	if err := tamper(func(e *crypto_utils.EnvelopeV2) { e.Signature = "" }); !errors.Is(err, crypto_utils.ErrMissingSignature) {
		t.Fatalf("missing signature: %v", err)
	}
	if err := tamper(func(e *crypto_utils.EnvelopeV2) { e.V = 1 }); !errors.Is(err, crypto_utils.ErrUnsupportedVer) {
		t.Fatalf("version: %v", err)
	}
	// Unverified decryption of a tampered payload still fails (GCM tag).
	e := *env
	e.Payload = flip(e.Payload)
	if _, err := c.DecryptPayloadV2(sPriv, "", &e); err == nil {
		t.Fatal("GCM accepted tampered payload")
	}
	if _, err := c.DecryptPayloadV2(sPriv, "", nil); !errors.Is(err, crypto_utils.ErrMissingField) {
		t.Fatalf("nil envelope: %v", err)
	}
}

func TestEnvelopeV2WithKeysVariants(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	sPrivS, sPubS, _, _ := mustV2Keys(t)
	_, _, dPrivS, dPubS := mustV2Keys(t)
	sPriv, _ := c.Base64ToX25519PrivateKey(sPrivS)
	sPub, _ := c.Base64ToX25519PublicKey(sPubS)
	dPriv, _ := c.Base64ToEd25519PrivateKey(dPrivS)
	dPub, _ := c.Base64ToEd25519PublicKey(dPubS)
	payload := []byte("keys v2")

	env, err := c.EncryptPayloadV2WithKeys(sPub, dPriv, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.DecryptPayloadV2(sPrivS, dPubS, env); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("string decrypt: %v", err)
	}
	env, _ = c.EncryptPayloadV2(sPubS, dPrivS, payload)
	if got, err := c.DecryptPayloadV2WithKeys(sPriv, dPub, env); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("keys decrypt: %v", err)
	}
	env, _ = c.EncryptPayloadV2WithKeys(sPub, nil, payload)
	if got, err := c.DecryptPayloadV2WithKeys(sPriv, nil, env); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("unsigned keys round trip: %v", err)
	}
}
