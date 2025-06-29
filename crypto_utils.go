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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// CryptoUtils
type CryptoUtils struct {
}

// NewCryptoUtils creates a new
func NewCryptoUtils() *CryptoUtils {
	return &CryptoUtils{}

}
func (c *CryptoUtils) GenerateRSAKeyPair() (string, string, error) {
	// Generate the RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Convert the private key to PKCS#8 PEM format (modern standard)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY", // PKCS#8 format (modern, generic)
		Bytes: privateKeyBytes,
	})

	// Convert the public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	// Convert the public key to PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY", // PKIX format (modern, generic)
		Bytes: publicKeyBytes,
	})

	privateKeyPEMString := base64.StdEncoding.EncodeToString(privateKeyPEM)
	publicKeyPEMString := base64.StdEncoding.EncodeToString(publicKeyPEM)
	// Return the PEM-encoded private and public keys as strings
	return privateKeyPEMString, publicKeyPEMString, nil
}

func (c *CryptoUtils) EncryptWithPublicKey(publicKey *rsa.PublicKey, message []byte) string {
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes)
}

// Converts a Base64-encoded PEM string to an *rsa.PrivateKey
func (c *CryptoUtils) Base64ToPrivateKey(base64PrivateKey string) (*rsa.PrivateKey, error) {
	// Decode the Base64 string
	pemBytes, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 private key: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid PEM block for private key")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return privateKey, nil
}

// Converts a Base64-encoded PEM string to an *rsa.PublicKey
func (c *CryptoUtils) Base64ToPublicKey(base64PublicKey string) (*rsa.PublicKey, error) {
	// Decode the Base64 string
	pemBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid PEM block for public key")
	}

	// Parse the public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	// Ensure the parsed key is an *rsa.PublicKey
	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parsed key is not an RSA public key")
	}

	return publicKey, nil
}
func (c *CryptoUtils) DecryptWithPrivateKey(privateKeyString string, encryptedMessage string) []byte {
	privateKey, err := c.Base64ToPrivateKey(privateKeyString)
	if err != nil {
		fmt.Println("Error: Failed to parse private key from base 64 string:", err)
		panic(err)
	}
	fmt.Println("Private Key Parsed successfully")
	encryptedBytes, _ := base64.StdEncoding.DecodeString(encryptedMessage)
	fmt.Println("Message decoded successfully")
	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedBytes)
	if err != nil {
		panic(err)
	}
	return decryptedBytes
}

func (c *CryptoUtils) EncryptWithAES(key, plaintext []byte) (ciphertext string, nonce []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	nonce = make([]byte, 12) // AES-GCM nonce size
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	ciphertextBytes := aesGCM.Seal(nil, nonce, plaintext, nil)
	ciphertext = base64.StdEncoding.EncodeToString(ciphertextBytes)
	return
}

func (c *CryptoUtils) DecryptWithAES(key, ciphertext, nonce []byte) string {
	ciphertextBytes, _ := base64.StdEncoding.DecodeString(string(ciphertext))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		panic(err)
	}
	return string(plaintext)
}

// SignWithPrivateKey signs the message using the private key (encrypt with private key)
func (c *CryptoUtils) SignWithPrivateKey(privateKeyString string, message []byte) string {
	privateKey, err := c.Base64ToPrivateKey(privateKeyString)
	if err != nil {
		panic(err)
	}
	hashed := sha256Sum(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

// VerifyWithPublicKey verifies the signature using the public key (decrypt with public key)
func (c *CryptoUtils) VerifyWithPublicKey(publicKeyString string, message []byte, base64Signature string) bool {
	publicKey, err := c.Base64ToPublicKey(publicKeyString)
	if err != nil {
		panic(err)
	}
	signature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		panic(err)
	}
	hashed := sha256Sum(message)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
	return err == nil
}

// helper function to calculate SHA256 hash
func sha256Sum(message []byte) []byte {
	hash := sha256.New()
	hash.Write(message)
	return hash.Sum(nil)
}
