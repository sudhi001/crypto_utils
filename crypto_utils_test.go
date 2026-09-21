package crypto_utils_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sudhi001/crypto_utils"
)

// legacyServerPrivateKey / legacyServerResponse were captured from a production
// Go backend and are shared with the Flutter test-suite; they pin the wire format.
const legacyServerPrivateKey = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBeTF5MDJZSHlqOENXcy9CaHlyZTFKMnBYaGlpLzVBRkdrZzNRZEltbGNWMWx2UnRtClRNUGpkWHNZYWtodi9RZUdKbzFFRUxtRWE5L1gvUm9xUzd2QWJ5S3A2SVJxYU1LQys5QUpJL1UzdjdmWTN1UzQKZEgySlFZaGh1WHVqb2xLak5HODBvd2pvK3drN1UwSy9qYVlGSWtvMjFZbTZVSFBuSVZFWHh4cTVSb2h3eFF2VApwZVlRdk1Yald0THdwKy9xQmZCOG5CK2MrSVBPVVhyeDdPdDQ2OERwU2x6T0NjR3c3azgzK1lFMTc3OElIRGJOCk5HamQyWGZwMzNMNHFVdytFSWE1U09qcllTRG5iU3E5Sk5XeGhITHgrLzAyZ0NycWFLOENoRXFZMGErTW9qWlMKSS9uS0Y3MVpMSFdsKzh6cUJOZUZEcWFSY25iRXVHYTAvSC83SlFJREFRQUJBb0lCQUV5T1ZGaXpoanhlbkgwVgp4OEs0UUw2YlZtS2ZjWW1rZjB3WlhqbVkzY3JkQmFGWXNMekNXNTBNMzRhWFNXMWdTVHkzSG9JTFROSU5YUEtmCnlIOWxLVTdOSmxodGpOOXVKa0FrczJReGVyQzJSYkszT01kRndRZUdEMy96andqYkFpeUpscSt2ZVlHVG1wMC8KK2Z1Wm5jSW9YUmNyTjVQMDVmUlJZbG1tY2t3ZUFrUDRFUEpGQXhuVGNFUHJpNE5MenEwekMrd0s4clBOSWN1bgpYWW02U2lwbC9kdlJHNkFaMC8wVDRxc244YlFCaVljY1FvMHFaNnZ5Qk9qU0JGMUFNZ3F1bm9NVTU2R0ZZNDlECkJyNHRDN1dzTDJaMDdEYzBnNndqeHZ5ZVR3UGFCdXpxMGY0ZjdySnBaTjZVeFJZRUkzM1cxN1lIVlZjb0d1VFoKTS9tSmdyc0NnWUVBNXd5Z0dFaFJzRWRrSnlmU0NuQ0VjVFVNZE1VVVB5b1M0NG4ySHNGMnd4Vkp2cGZKUUttcgo1Rm8wMlZLdXI2LzAxZWtJZy9VVHNCdlROcTk5azlSM0dDTnJYbllZZlA0cVdlR3JkNGlMbzJndVZXZHEyQlduCnhZVW5HZFlJdVVEZE9COTVpSTZpSU9MMVpQclhwWEc0dG5sajBuNnhQKy9rRTljNGFOcGRTWThDZ1lFQTRWS3EKdk9uUHB5dDRmVkh1b3pwN2tqVHlrUTVPRXNzUXQ0MjNPeTVua2R4cmZhQ1czanNZRGhpQy9KYnVDSmVYaXlwSgpDTitSNUhHZjBHOUtsa0dlR3BJUUtYQzg0cGpqaFpoV1JRMmpNYjJURjZYRVp0bkgxNHE3RENORFd4R0kxNHN6CnRpOXo0dS9FWGE0VWU1QkVIVEcrdG5ocDlIOGc3ZW5zQW93SURnc0NnWUVBd3VSYWNzRWw3c3o1aFRISXNiZWgKY0NDd1Joc3JiZkJlaUlLS0VmMWM0VWVtc2RjMUVvOU1pRTB6QVJJR2VmbXhTM0xMRlF2NE5IZjBITS9BM0o2KwphcVVOMzFzOFlzcStESjBYMXJkZUdsTTVxaDZXK0hpajBTLzFBSTBUUkxpYklja2k2Zlp1ZWRFWDc3ckxoaW04CkJtZTB0UXpiRkxTVXJjdkFNR25wZ0s4Q2dZQms1NlZvaG5pa3ozWGRBV1VTR2kyZWt6R1J2a3MrWlV2dU4zdTMKK0JjUG5odFJIaXFTQ1ByRHpUeFRxNitiajIraE5lV1JJTFh3RE9aWjdJMEZid3REc09lbDkwUFBZbEo1MEhmSgo0c3FUaXVjbGJ1bmVlV2JpWXRGVEpUT1R3KzE1UVhCK0JSQXJyOTVMYVpyb252bXg3VVlQNXlya0FFNlozT2tCClZ2NkFjd0tCZ0JDUnZob21XaDVyeE1xa3RCdWlTekhaNStVT2d0by9LMzJNM0xPQnhrSU41WlZ4RDVsd2J4WGUKN1h3QUZuUzFCMWRkbUhaQXNGTGFObUFyb0hBVFpQcU40NzM3M1EyZXR6aGg5OExjNnRBZUM4NkYrUGVVUWUrdQpMUFBLaTc2VzNHOGhhVG5oeHlKcXhaRmZrcTd5T2E1TGRvdkx6V3JKVUtJRWV4VXZBVnFCCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="

const legacyServerResponse = `{
  "Payload": "/uNtQlCaHUfLnqx7ML4HbtzwDhzA+9g6p/nlTI8mFHcJDeVX3ZfZIKgs2iH6e1lAMaMcKoYnWAZfdDLMTrWj69tx6VKK9eL2bI9MfNWmgTwJZXeOWQPQreXhzvbeTlzUcPtD9jvU23Q4dzgyNwvtibC9IVp/lVKZ/ERzy6G4vZ9dmeyMosTxaC95ytfW+4HSuZC3fnT/QPB7KydfS5zwh9rUBympku2wkW4hUdBIkd6pJpsyCHe53nfZUrUVNBFVmi6gLDulGeQPiZ1FjGnDjHnyDwJ+lpbT3554sVIfFPCq3uUdW0amZEu0vyC2CT8pSi7CPOtjSgufKdKl+Mb1WcEW59U+oqvXllg1p4oyfhamyutUNq+eAvsubMCzIbpAWOP59Vm8AeJMLGYU1Y1Crk9L/oqpdJJt2MhtnWjqZil9MQwzjgx6JGmy2pOk7pgS9+w4ufHKE2lhgOTQkryzdQpbHfbTEY5hw5m//v4Qdd9pMYSTLeyvhfXExQBfdUpwUPBjKoMIi6gZEyAPWlE2oKM6g4wDyoFSzA5vOz0d6wbeHw3Kr9qNLxT1URXdZYW7mmG/iZWQt+tGtyUgyEtKgRhvXKYX3JGEfQBUnmoH83KRw6O8JHWWtmJTWmA3FCjVIKDcSvvKoTXzILhtmZ5Wvzr+KQQlR1kOPC1lOxIRYa0smmFM0r8PJAI9ovvD1NPIErxQ/mx8TWHE4U9DAPk8c9U5PC/hGoX1E6WWMeOWn7jA5BLB6+IQe4ef/AO6fvS4mWwpFARNdC5yB55TXLQi6PolKicxa2tCXd/gD/0N8e9vYGZ3LLu3sUaCGtXz4BT8aUucZRy/+5qj31sQs1S1D07HHCFCH+epKqRF0TeNycroKCACdO1ZckbzDcYMblwhadLpyy853fM0hxnerMhqhUxwX3FEue5GR1nSdmrpObnMQ6tOi2b4zFjK2x6ShttA1596Jti53rRn9ltCElM8QpvFrx5OYnBCkVQgnxMBlzgaDHpi3MrgTVTOCJSSUJDaSJ9lj+H1eKXUHVyhjy0RMXbC66d88ecwtkhWQLv9lPrEQ3vq/yITfXfh3/dpdpuxpsYEKt3m31as0y0ONtPRAQ18X9iWGMGWUibRtxATKHzPeCx1RwUOlSrwbPoh2gGpA/bj3bAUIujs0UH+O4GYS2ZYabKH9HP/0oQ4BPNjTNlios5Z8z/m41gmliR6mx0Zd24kGg4GstNG6c50QIe/J9jf9xhn9uzElrPfW/bMYwPpVFv4kiM9SAh8VGT0PDkycCUDH/yOKkO2m4OR7H8RsnbbCTFQIH4GsQFLq/MMR35IHomR9gXVE825tmwhrgw2DtURRbNHtF38LF6NoO8DjoinUFOrmbMKudBbQbobg5cVCzUPrr8OWdR5B19KrwLkuliaGh+ll//3KTdJLz7Ntlz91daE4oVtH/2kTg8Zw3hAXd/TgFW49OoRbWRPM2isooz5fECniFZOwm3/KE8DIU7gMYiXP5ZJwkfm2sH1tw==",
  "Key": "tvZgHRj4ICqAa1YmgW1Ht7zw1SdR2hg3BhMvdxPcFDm0/3kG4xRRT3V0B+BclqljRLKIuVBsdVOIWCjnUrMvB0aXEXZUPIMci0IeBkKFd++gdwieLKONeJMEGiuQqDuxJUvTvjVEBM2EbQ6uh1LsbT4+XhQctlITIA0TNNSAgJ3uMgyG82R/+q37ZIZxJFCZpWqjctk79YKUHih9WiPrcwEvzVGsr3utOnkrZngEqkeEAeGi5DDu5UHOT7EHPAgTAPFGg/wuiue1N/PoA/QhSPYnusC2vtiCZo69usc3tiqdsLhwLgusOOHxLg6KSZifww8jrgBZmJHxXh7/+PYB1w==",
  "Nonce": "yok6ogjvWG24NeMD"
}`

func mustKeyPair(t *testing.T) (string, string) {
	t.Helper()
	priv, pub, err := crypto_utils.NewCryptoUtils().GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	return priv, pub
}

func TestGenerateRSAKeyPairProducesBase64PEM(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)

	privPEM, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || !strings.HasPrefix(string(privPEM), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatalf("private key is not base64(PKCS#1 PEM): %v", err)
	}
	pubPEM, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || !strings.HasPrefix(string(pubPEM), "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("public key is not base64(PKIX PEM): %v", err)
	}

	if _, err := c.Base64ToPrivateKey(priv); err != nil {
		t.Fatalf("Base64ToPrivateKey: %v", err)
	}
	if _, err := c.Base64ToPublicKey(pub); err != nil {
		t.Fatalf("Base64ToPublicKey: %v", err)
	}
}

func TestKeyParsingRejectsGarbage(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	if _, err := c.Base64ToPrivateKey("not base64!"); err == nil {
		t.Error("expected base64 error for private key")
	}
	if _, err := c.Base64ToPublicKey(base64.StdEncoding.EncodeToString([]byte("no pem here"))); err == nil {
		t.Error("expected PEM error for public key")
	}
	// Public PEM handed to the private parser must be rejected.
	priv, pub := mustKeyPair(t)
	if _, err := c.Base64ToPrivateKey(pub); err == nil {
		t.Error("expected error parsing public key as private")
	}
	if _, err := c.Base64ToPublicKey(priv); err == nil {
		t.Error("expected error parsing private key as public")
	}
}

func TestRSAPKCS1v15RoundTrip(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)
	message := []byte("Hello, secure world!")

	encrypted, err := c.EncryptRSA(pub, message)
	if err != nil {
		t.Fatalf("EncryptRSA: %v", err)
	}
	decrypted, err := c.DecryptWithPrivateKey(priv, encrypted)
	if err != nil {
		t.Fatalf("DecryptWithPrivateKey: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}

	// Legacy *rsa.PublicKey based API must produce compatible ciphertext.
	pubKey, _ := c.Base64ToPublicKey(pub)
	decrypted, err = c.DecryptRSA(priv, c.EncryptWithPublicKey(pubKey, message))
	if err != nil || !bytes.Equal(decrypted, message) {
		t.Fatalf("legacy EncryptWithPublicKey round trip failed: %v", err)
	}
}

func TestRSAOAEPRoundTrip(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)
	message := []byte("OAEP message")

	encrypted, err := c.EncryptWithPublicKeyOAEP(pub, message)
	if err != nil {
		t.Fatalf("EncryptWithPublicKeyOAEP: %v", err)
	}
	decrypted, err := c.DecryptWithPrivateKeyOAEP(priv, encrypted)
	if err != nil {
		t.Fatalf("DecryptWithPrivateKeyOAEP: %v", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}
	// OAEP ciphertext must not open with PKCS#1 v1.5.
	if _, err := c.DecryptWithPrivateKey(priv, encrypted); err == nil {
		t.Fatal("PKCS#1 v1.5 decryption of OAEP ciphertext unexpectedly succeeded")
	}
}

func TestRSAWrongKeyFails(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	_, pub := mustKeyPair(t)
	otherPriv, _ := mustKeyPair(t)
	encrypted, _ := c.EncryptRSA(pub, []byte("secret"))
	if _, err := c.DecryptWithPrivateKey(otherPriv, encrypted); err == nil {
		t.Fatal("decryption with wrong private key unexpectedly succeeded")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	key, _ := c.GenerateRandomBytes(crypto_utils.AESKeySize)
	plaintext := []byte(`{"Code":"172","Amount":100.0,"Currency":"INR"}`)

	ciphertext, nonce, err := c.EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}
	decrypted, err := c.DecryptAESGCM(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("DecryptAESGCM: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}

	// Legacy helpers must be compatible with the new ones.
	nonceBytes, _ := base64.StdEncoding.DecodeString(nonce)
	if got := c.DecryptWithAES(key, []byte(ciphertext), nonceBytes); got != string(plaintext) {
		t.Fatalf("legacy DecryptWithAES mismatch: %q", got)
	}
	legacyCT, legacyNonce := c.EncryptWithAES(key, plaintext)
	decrypted, err = c.DecryptAESGCM(key, legacyCT, base64.StdEncoding.EncodeToString(legacyNonce))
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("legacy EncryptWithAES round trip failed: %v", err)
	}
}

func TestAESGCMRejectsWrongKeyAndTamper(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	key, _ := c.GenerateRandomBytes(32)
	wrongKey, _ := c.GenerateRandomBytes(32)
	ciphertext, nonce, _ := c.EncryptAESGCM(key, []byte("data"))

	if _, err := c.DecryptAESGCM(wrongKey, ciphertext, nonce); err == nil {
		t.Fatal("wrong key unexpectedly succeeded")
	}
	raw, _ := base64.StdEncoding.DecodeString(ciphertext)
	raw[0] ^= 0xff
	if _, err := c.DecryptAESGCM(key, base64.StdEncoding.EncodeToString(raw), nonce); err == nil {
		t.Fatal("tampered ciphertext unexpectedly succeeded")
	}
	if _, _, err := c.EncryptAESGCM(key[:16], []byte("x")); !errors.Is(err, crypto_utils.ErrInvalidKeyLength) {
		t.Fatalf("expected ErrInvalidKeyLength, got %v", err)
	}
}

func TestAESGCMKnownVector(t *testing.T) {
	// Vector produced by the Flutter package; pins the GCM layout (tag appended, no AAD).
	c := crypto_utils.NewCryptoUtils()
	key, _ := base64.StdEncoding.DecodeString("NwUqUByc21I71POTifDQ1OPjhwBIFNd1Q2wodYbxOkE=")
	plaintext, err := c.DecryptAESGCM(key, "AHlo1s9rKPRSL3qTv9LqN+giCtQ9", "/jy/osqLyF8pgnI8")
	if err != nil {
		t.Fatalf("DecryptAESGCM: %v", err)
	}
	if len(plaintext) == 0 {
		t.Fatal("empty plaintext")
	}
}

func TestSignAndVerify(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)
	_, otherPub := mustKeyPair(t)
	message := []byte("sign me")

	sig, err := c.Sign(priv, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if ok, err := c.Verify(pub, message, sig); err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := c.Verify(pub, []byte("sign me!"), sig); ok {
		t.Fatal("signature verified for altered message")
	}
	if ok, _ := c.Verify(otherPub, message, sig); ok {
		t.Fatal("signature verified with wrong public key")
	}
	if _, err := c.Verify(pub, message, "!!"); err == nil {
		t.Fatal("expected error for undecodable signature")
	}
	// Legacy wrappers.
	if !c.VerifyWithPublicKey(pub, message, c.SignWithPrivateKey(priv, message)) {
		t.Fatal("legacy sign/verify failed")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	serverPriv, serverPub := mustKeyPair(t)
	payload := []byte(`{"hello":"world","n":1}`)

	env, err := c.EncryptPayload(serverPub, payload)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if env.Signature != "" {
		t.Fatal("unsigned envelope carries a signature")
	}
	decrypted, err := c.DecryptPayload(serverPriv, env)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}

	// JSON representation uses lowercase keys and omits an empty signature.
	data, _ := json.Marshal(env)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for _, k := range []string{"payload", "key", "nonce"} {
		if _, ok := m[k]; !ok {
			t.Errorf("envelope JSON missing %q: %s", k, data)
		}
	}
	if _, ok := m["signature"]; ok {
		t.Errorf("envelope JSON should omit empty signature: %s", data)
	}
}

func TestEnvelopeOAEPRoundTrip(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)
	env, err := c.EncryptPayloadOAEP(pub, []byte("oaep payload"))
	if err != nil {
		t.Fatalf("EncryptPayloadOAEP: %v", err)
	}
	decrypted, err := c.DecryptPayloadOAEP(priv, env)
	if err != nil || string(decrypted) != "oaep payload" {
		t.Fatalf("DecryptPayloadOAEP: %q %v", decrypted, err)
	}
	if _, err := c.DecryptPayload(priv, env); err == nil {
		t.Fatal("PKCS#1 v1.5 DecryptPayload of OAEP envelope unexpectedly succeeded")
	}
}

func TestEnvelopeSignedRoundTrip(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	serverPriv, serverPub := mustKeyPair(t)
	devicePriv, devicePub := mustKeyPair(t)
	_, strangerPub := mustKeyPair(t)
	payload := []byte("signed payload")

	env, err := c.EncryptPayloadSigned(serverPub, devicePriv, payload)
	if err != nil {
		t.Fatalf("EncryptPayloadSigned: %v", err)
	}
	decrypted, err := c.DecryptPayloadVerified(serverPriv, devicePub, env)
	if err != nil || !bytes.Equal(decrypted, payload) {
		t.Fatalf("DecryptPayloadVerified: %q %v", decrypted, err)
	}

	if _, err := c.DecryptPayloadVerified(serverPriv, strangerPub, env); !errors.Is(err, crypto_utils.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}

	tampered := *env
	raw, _ := base64.StdEncoding.DecodeString(tampered.Payload)
	raw[len(raw)-1] ^= 1
	tampered.Payload = base64.StdEncoding.EncodeToString(raw)
	if _, err := c.DecryptPayloadVerified(serverPriv, devicePub, &tampered); !errors.Is(err, crypto_utils.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature for tampered payload, got %v", err)
	}

	unsigned := *env
	unsigned.Signature = ""
	if _, err := c.DecryptPayloadVerified(serverPriv, devicePub, &unsigned); !errors.Is(err, crypto_utils.ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}
	// Unverified decryption still works without a signature.
	if _, err := c.DecryptPayload(serverPriv, &unsigned); err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
}

func TestEnvelopeMissingFields(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, _ := mustKeyPair(t)
	if _, err := c.DecryptPayload(priv, nil); !errors.Is(err, crypto_utils.ErrMissingField) {
		t.Fatalf("expected ErrMissingField for nil, got %v", err)
	}
	if _, err := c.DecryptPayload(priv, &crypto_utils.Envelope{Key: "x"}); !errors.Is(err, crypto_utils.ErrMissingField) {
		t.Fatalf("expected ErrMissingField, got %v", err)
	}
}

func TestEnvelopeAcceptsLegacyBase64Key(t *testing.T) {
	// Older Flutter clients RSA-encrypted the base64 *text* of the AES key
	// (44 bytes) instead of the raw 32 bytes. The server must still accept it.
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)
	aesKey, _ := c.GenerateRandomBytes(32)
	payload := []byte("legacy client payload")

	ciphertext, nonce, _ := c.EncryptAESGCM(aesKey, payload)
	legacyKey, _ := c.EncryptRSA(pub, []byte(base64.StdEncoding.EncodeToString(aesKey)))
	env := &crypto_utils.Envelope{Payload: ciphertext, Nonce: nonce, Key: legacyKey}

	decrypted, err := c.DecryptPayload(priv, env)
	if err != nil || !bytes.Equal(decrypted, payload) {
		t.Fatalf("legacy key envelope: %q %v", decrypted, err)
	}
}

func TestEnvelopeRejectsBadKeyLength(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)
	aesKey, _ := c.GenerateRandomBytes(32)
	ciphertext, nonce, _ := c.EncryptAESGCM(aesKey, []byte("x"))
	badKey, _ := c.EncryptRSA(pub, aesKey[:16])
	if _, err := c.DecryptPayload(priv, &crypto_utils.Envelope{Payload: ciphertext, Nonce: nonce, Key: badKey}); err == nil {
		t.Fatal("expected error for 16-byte AES key")
	}
}

func TestDecryptLegacyServerResponse(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	var env crypto_utils.Envelope
	if err := json.Unmarshal([]byte(legacyServerResponse), &env); err != nil {
		t.Fatalf("unmarshal (uppercase field names must be accepted): %v", err)
	}
	if env.Payload == "" || env.Key == "" || env.Nonce == "" {
		t.Fatal("uppercase JSON fields were not mapped onto Envelope")
	}

	var response map[string]any
	if err := c.DecryptJSON(legacyServerPrivateKey, &env, &response); err != nil {
		t.Fatalf("DecryptJSON: %v", err)
	}
	if response["Code"] != "118" || response["Duration"] != float64(12) {
		t.Fatalf("unexpected decrypted content: Code=%v Duration=%v", response["Code"], response["Duration"])
	}
}

func TestEncryptDecryptJSON(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	priv, pub := mustKeyPair(t)
	type order struct {
		Code   string  `json:"code"`
		Amount float64 `json:"amount"`
	}
	env, err := c.EncryptJSON(pub, order{Code: "172", Amount: 100})
	if err != nil {
		t.Fatalf("EncryptJSON: %v", err)
	}
	var got order
	if err := c.DecryptJSON(priv, env, &got); err != nil {
		t.Fatalf("DecryptJSON: %v", err)
	}
	if got.Code != "172" || got.Amount != 100 {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestWithKeysVariantsMatchStringAPI(t *testing.T) {
	c := crypto_utils.NewCryptoUtils()
	serverPrivS, serverPubS := mustKeyPair(t)
	devicePrivS, devicePubS := mustKeyPair(t)
	serverPriv, _ := c.Base64ToPrivateKey(serverPrivS)
	serverPub, _ := c.Base64ToPublicKey(serverPubS)
	devicePriv, _ := c.Base64ToPrivateKey(devicePrivS)
	devicePub, _ := c.Base64ToPublicKey(devicePubS)
	payload := []byte("keys variant")

	for _, oaep := range []bool{false, true} {
		env, err := c.EncryptPayloadWithKeys(serverPub, devicePriv, payload, oaep)
		if err != nil {
			t.Fatalf("EncryptPayloadWithKeys oaep=%v: %v", oaep, err)
		}
		var got []byte
		if oaep {
			got, err = c.DecryptPayloadVerifiedOAEP(serverPrivS, devicePubS, env)
		} else {
			got, err = c.DecryptPayloadVerified(serverPrivS, devicePubS, env)
		}
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("string decrypt of keys envelope oaep=%v: %q %v", oaep, got, err)
		}
		if oaep {
			env, err = c.EncryptPayloadSignedOAEP(serverPubS, devicePrivS, payload)
		} else {
			env, err = c.EncryptPayloadSigned(serverPubS, devicePrivS, payload)
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err = c.DecryptPayloadWithKeys(serverPriv, devicePub, env, oaep)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("keys decrypt of string envelope oaep=%v: %q %v", oaep, got, err)
		}
		if _, err := c.DecryptPayloadWithKeys(serverPriv, serverPub, env, oaep); !errors.Is(err, crypto_utils.ErrBadSignature) {
			t.Fatalf("expected ErrBadSignature, got %v", err)
		}
		env, _ = c.EncryptPayloadWithKeys(serverPub, nil, payload, oaep)
		if env.Signature != "" {
			t.Fatal("nil signer produced a signature")
		}
		if got, err = c.DecryptPayloadWithKeys(serverPriv, nil, env, oaep); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("unsigned keys round trip: %v", err)
		}
	}

	ct, _ := c.EncryptRSAWithKey(serverPub, payload, false)
	if pt, err := c.DecryptWithPrivateKey(serverPrivS, ct); err != nil || !bytes.Equal(pt, payload) {
		t.Fatalf("EncryptRSAWithKey: %v", err)
	}
	sig, _ := c.SignWithKey(devicePriv, payload)
	if ok, err := c.Verify(devicePubS, payload, sig); err != nil || !ok {
		t.Fatalf("SignWithKey: ok=%v err=%v", ok, err)
	}
	if _, err := c.DecryptPayloadWithKeys(serverPriv, nil, nil, false); !errors.Is(err, crypto_utils.ErrMissingField) {
		t.Fatalf("expected ErrMissingField, got %v", err)
	}
}
