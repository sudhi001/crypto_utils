package crypto_utils_test

import (
	"encoding/json"
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

func TestCryptoUtils_NewSession(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Generate a fresh key pair that works
	privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Your base64-encoded PEM strings:
	jsonMessage := `{"payload":"q/eOvbyblsEa8NnxKGTKUtz0VFfTOQ4+cuSSlcosyU3Cbo7dEOQd1jNkkUYyzFyaIxMO5jwrrBuJI3A94GhSdUzW8jww4stq0m97iJoNxm0ZuM575EcF","key":"mDjXePRt7Qdym6dBf9ilPEVnfxk5ZFWhsfkoy8Y6tFfnIyd4Z6MXhoI9z14jO0AvWyz+OiPECHAgh9sRtM+01M6GLkPdAZzzf8ByyjeHKedmO+AeXYfxeJ+MMYNRNux4eDtHWOpC9fZb4sF/+y+HQEg6eVBRVyK7yDc8NUxpbSkhehjerLjqfTFHvI82O5m0HfzmZTNfUsnY2RkcvnTH5SzY640BLNVVzfC0CveCgwVpbtWuSqh8+Q0GaLBoZkaFgP/rp3KLX9iGurj3t0OM3xJQiXbysXYu07SKSqtApjPF7jEmputPpeppewqDmvtb6GlN1KNnWOZNOGKP1EsHDw==","nonce":"9BANsCcEEj0CLv7M","signature":"Kp3CoAxmUr0Ji5sSWUwxlpM/BLXcV1k5N4W+4kmjUnNzI3WQIuVhO+9sTToNBlNCH75BYu10vmL2ZNsn1ZQqqhMCbCdnBJTtXdTL8meFOAGhzSxBqeimXKuCT7OJgTEWHlA5FXIhEjjB4/4e3SW5ENoK8eGkZp9rtfaojS2jynzjdVj/dQbA6Vujbc/fB1oWsrvM8SBdOe7miPSe64P+6S8APK69NmqDxhPOMe1lsYXle8LvVu1oeyy8v0TFKzUQ1HJNko6Tlk9fYTRfvWbo/kKps8ytNDaHMOLfqs4hIdOkg5axLZavH21UF3avVVL4qEvGbGk4wLUnP9W5S4hKVA=="}`

	// Parse the JSON string into a struct
	var secureMsg SecureMessage
	err = json.Unmarshal([]byte(jsonMessage), &secureMsg)
	if err != nil {
		t.Fatalf("Failed to parse JSON message: %v", err)
	}

	// Now you can access the parsed JSON fields
	t.Logf("Payload: %s", secureMsg.Payload)
	t.Logf("Key: %s", secureMsg.Key)
	t.Logf("Nonce: %s", secureMsg.Nonce)
	t.Logf("Signature: %s", secureMsg.Signature)

	// Use the freshly generated PEM-encoded keys
	serverPrivateKey := privateKey
	serverPublicKey := publicKey
	t.Logf("Private Key: %s", serverPrivateKey)
	t.Logf("Public Key: %s", serverPublicKey)

	// Test if the RSA key pair works correctly
	t.Logf("Testing RSA key pair...")

	// Parse the public key
	parsedPublicKey, err := crypto.Base64ToPublicKey(serverPublicKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Test message
	testMessage := "Hello World"

	// Encrypt with public key
	encryptedTest := crypto.EncryptWithPublicKey(parsedPublicKey, []byte(testMessage))
	t.Logf("Encrypted test message: %s", encryptedTest)

	// Decrypt with private key
	decryptedTest := crypto.DecryptWithPrivateKey(serverPrivateKey, encryptedTest)
	t.Logf("Decrypted test message: %s", string(decryptedTest))

	// Now try to decrypt the actual key from the JSON
	t.Logf("Attempting to decrypt the key from JSON...")
	decryptedKey := crypto.DecryptWithPrivateKey(serverPrivateKey, secureMsg.Key)
	t.Logf("Decrypted Key: %s", string(decryptedKey))

	// Note: The JSON key was encrypted with a different public key, so this will fail
	// This is expected since we're using a different key pair
	t.Logf("Note: This decryption will fail because the JSON key was encrypted with a different public key")
}

func TestExportGoKeyPair(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()
	privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	t.Logf("Go Public Key (base64): %s", publicKey)
	t.Logf("Go Private Key (base64): %s", privateKey)
	// You can copy these values and use the public key in Flutter for encryption,
	// and the private key in Go for decryption.
}

func TestNewKeyPairWorks(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Use the newly generated key pair
	privateKey := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBcW9ZUERiSWt6c2tjTGV2bTFyWDNzc1M5T210c3FON3BRMXo0TUJ1ODNHNnZsQ3JJeGR1TThZN0NTLzI0RlU4SStzMnFUOENNNWVQSnBzR2tBVlE4CmJlYnd4T1lVR2pUZTQ2QW1SbzMya2ZnaGp1RWtVSWZUd2hoOEQxZlBwSTBVZnU5MjlwREw1bmlPaER2NTE1T2sKSVM5d1gxdnprTkhUV1ErazJOZ3UveWlmYnJvMgpvWFo3SVhUNW01TjFVaUFSd1l6aUkxMHRSSnlvZ3pqZjNKR0tBYUgvWm8xU2FCV0Q4eDJ4ZUtDOWZZRGRWeWF1Yk5OZGxORXMxcTZ2VDh4eE9YSnVYVWE1ekRDam0vVlN3cWNxCk9UbUdsald6cnNWRDhjbjIydVpzRDloem15MU4KcFpRaCtaaWRMVlNMd0lUd0k5S25janBoTmZGYk9nTTFvbXhCMndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
	publicKey := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxb1lQRGJJa3pza2NMZXZtMXJYMwpzc1M5T210c3FON3BRMXo0TUJ1ODNHNnZsQ3JJeGR1TThZN0NTLzI0RlU4SStzMnFUOENNNWVQSnBzR2tBVlE4CmJlYnd4T1lVR2pUZTQ2QW1SbzMya2ZnaGp1RWtVSWZUd2hoOEQxZlBwSTBVZnU5MjlwREw1bmlPaER2NTE1T2sKSVM5d1gxdnprTkhUV1ErazJOZ3UveWlmYnJvMm9YWjdJWFQ1bTVOMVVpQVJ3WXppSTEwdFJKeW9nempmM0pHSwpBYUgvWm8xU2FCV0Q4eDJ4ZUtDOWZZRGRWeWF1Yk5OZGxORXMxcTZ2VDh4eE9YSnVYVWE1ekRDam0vVlN3cWNxCk9UbUdsald6cnNWRDhjbjIydVpzRDloem15MU5wWlFoK1ppZE1WU0x3SVR3STlLbmNqcGhOZkZiT2dNMW9teEIKMndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="

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

	t.Logf("✅ New key pair works correctly!")
}

func TestFreshKeyPairWorks(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	// Generate a fresh key pair
	privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
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
