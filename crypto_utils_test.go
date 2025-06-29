package crypto_utils_test

import (
	"encoding/base64"
	"testing"

	"github.com/sudhi001/crypto_utils"
)

// SecureMessage represents the structure of the JSON message
type SecureMessage struct {
	Payload   string `json:"payload"`
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

func TestGenerateAESWithSignature(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Generate compatible key pair
	privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate compatible RSA key pair: %v", err)
	}

	// Test data - same as Flutter test
	plaintext := `{"Code":"172","Amount":100.0,"Currency":"INR"}`

	// Generate random AES key (32 bytes = 256 bits)
	aesKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random AES key: %v", err)
	}

	// Encrypt with AES
	encryptedAES, nonce := crypto.EncryptWithAES(aesKey, []byte(plaintext))
	t.Logf("Encrypted AES: %s", encryptedAES)
	t.Logf("Nonce: %s", base64.StdEncoding.EncodeToString(nonce))

	// Generate signature using private key
	signature := crypto.SignWithPrivateKey(privateKey, []byte(encryptedAES))
	t.Logf("Signature AES: %s", signature)

	// Decrypt with AES
	decryptedAES := crypto.DecryptWithAES(aesKey, []byte(encryptedAES), nonce)
	t.Logf("Decrypted AES: %s", decryptedAES)

	// Verify the decrypted message matches the original plaintext
	if decryptedAES != plaintext {
		t.Fatalf("Decrypted message doesn't match original. Expected: %s, Got: %s", plaintext, decryptedAES)
	}

	// Verify signature with public key
	isVerified := crypto.VerifyWithPublicKey(publicKey, []byte(encryptedAES), signature)
	if !isVerified {
		t.Fatalf("Signature verification failed")
	}

	t.Logf("✅ Test passes since the decrypted message matches the original plaintext")
}

func TestRSAEncryptWithPublicKeyAndDecryptWithPrivateKey(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Generate compatible key pair
	privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate compatible RSA key pair: %v", err)
	}

	// Generate random symmetric key (same as Flutter test)
	symmetricKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random symmetric key: %v", err)
	}

	plaintext := base64.StdEncoding.EncodeToString(symmetricKey)
	t.Logf("Key for encryption: %s", plaintext)

	// Parse the public key
	parsedPublicKey, err := crypto.Base64ToPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Encrypt with public key
	encryptedMessage := crypto.EncryptWithPublicKey(parsedPublicKey, []byte(plaintext))
	t.Logf("Encrypted message (Base64): %s", encryptedMessage)

	// Decrypt with private key
	decrypted := crypto.DecryptWithPrivateKey(privateKey, encryptedMessage)
	decryptedText := string(decrypted)
	t.Logf("Decrypted message: %s", decryptedText)

	// Verify the decrypted message matches the original plaintext
	if decryptedText != plaintext {
		t.Fatalf("Decrypted message doesn't match original. Expected: %s, Got: %s", plaintext, decryptedText)
	}

	t.Logf("✅ Test passes since the decrypted message matches the original plaintext")
}

func TestAESEncryptionAndDecryption(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Test data - same as Flutter test
	plaintext := `{"Code":"172","Amount":100.0,"Currency":"INR"}`

	// Generate random AES key (32 bytes = 256 bits)
	aesKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random AES key: %v", err)
	}

	// Encrypt with AES
	encryptedAES, nonce := crypto.EncryptWithAES(aesKey, []byte(plaintext))
	t.Logf("Encrypted AES: %s", encryptedAES)

	// Decrypt with AES
	decryptedAES := crypto.DecryptWithAES(aesKey, []byte(encryptedAES), nonce)
	t.Logf("Decrypted AES: %s", decryptedAES)

	// Verify the decrypted message matches the original plaintext
	if decryptedAES != plaintext {
		t.Fatalf("Decrypted message doesn't match original. Expected: %s, Got: %s", plaintext, decryptedAES)
	}

	t.Logf("✅ Test passes since the decrypted message matches the original plaintext")
}

func TestAESDecryptionFailureWithWrongKey(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Test data - same as Flutter test
	plaintext := `{"Code":"172","Amount":100.0,"Currency":"INR"}`

	// Generate correct AES key
	correctKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random AES key: %v", err)
	}

	// Generate wrong AES key
	wrongKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random wrong AES key: %v", err)
	}

	// Encrypt with AES using the correct key
	encryptedAES, nonce := crypto.EncryptWithAES(correctKey, []byte(plaintext))
	t.Logf("Encrypted AES: %s", encryptedAES)

	// Try to decrypt with a wrong key and ensure it fails
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("Decryption should fail with the wrong key")
		} else {
			t.Logf("Decryption failed as expected with wrong key: %v", r)
			t.Logf("✅ Test passes since decryption failed with wrong key")
		}
	}()

	// This should panic due to wrong key
	_ = crypto.DecryptWithAES(wrongKey, []byte(encryptedAES), nonce)
}

func TestFreshKeyPairWorks(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Generate compatible key pair
	privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate compatible RSA key pair: %v", err)
	}

	t.Logf("Generated Private Key: %s", privateKey)
	t.Logf("Generated Public Key: %s", publicKey)

	// Test message
	testMessage := "Hello World"

	// Parse the public key
	parsedPublicKey, err := crypto.Base64ToPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Encrypt with public key
	encryptedTest := crypto.EncryptWithPublicKey(parsedPublicKey, []byte(testMessage))
	t.Logf("Encrypted test message: %s", encryptedTest)

	// Decrypt with private key
	decryptedTest := crypto.DecryptWithPrivateKey(privateKey, encryptedTest)
	t.Logf("Decrypted test message: %s", string(decryptedTest))

	// Verify the result
	if string(decryptedTest) != testMessage {
		t.Fatalf("Decrypted message doesn't match original")
	}

	t.Logf("✅ Fresh key pair works correctly!")
}

func TestExportGoKeyPair(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()
	privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate compatible RSA key pair: %v", err)
	}
	t.Logf("Go Public Key (base64): %s", publicKey)
	t.Logf("Go Private Key (base64): %s", privateKey)
	// You can copy these values and use the public key in Flutter for encryption,
	// and the private key in Go for decryption.
}
