# crypto_utils

`crypto_utils` is a Go package that simplifies cryptographic operations like RSA key pair generation, encryption/decryption using RSA and AES, and encoding/decoding of keys. The package is designed to help developers securely handle encryption needs with ease.

## Features

- Generate RSA key pairs (private and public keys).
- Encrypt and decrypt messages using RSA public and private keys.
- Encrypt and decrypt messages using AES-GCM (with a randomly generated nonce).
- Convert Base64-encoded PEM strings into RSA keys.
- Utility functions for encoding and decoding cryptographic data.

## Installation

Use `go get` to install the package:

```bash
go get github.com/sudhi001/crypto_utils
```

## Usage

### Import the Package

```go
import "github.com/sudhi001/crypto_utils"
```

### Example: RSA Key Pair Generation

```go
crypto := crypto_utils.NewCryptoUtils()

privateKey, publicKey, err := crypto.GenerateRSAKeyPair()
if err != nil {
    panic(err)
}
fmt.Println("Private Key:", privateKey)
fmt.Println("Public Key:", publicKey)
```

### Example: RSA Encryption and Decryption

```go
// Initialize CryptoUtils
crypto := crypto_utils.NewCryptoUtils()

// Example public and private keys
publicKeyString := "BASE64_ENCODED_PUBLIC_KEY"
privateKeyString := "BASE64_ENCODED_PRIVATE_KEY"

// Convert public key from Base64 to *rsa.PublicKey
publicKey, _ := crypto.Base64ToPublicKey(publicKeyString)

// Encrypt a message using the public key
message := []byte("Hello, secure world!")
encryptedMessage := crypto.EncryptWithPublicKey(publicKey, message)
fmt.Println("Encrypted Message:", encryptedMessage)

// Decrypt the message using the private key
decryptedMessage := crypto.DecryptWithPrivateKey(privateKeyString, encryptedMessage)
fmt.Println("Decrypted Message:", string(decryptedMessage))
```

### Example: AES Encryption and Decryption

```go
// AES key (32 bytes for AES-256)
symmetricKey := make([]byte, 32)
_, err := rand.Read(symmetricKey)
if err != nil {
    panic(err)
}

// Encrypt a message
plaintext := []byte("Sensitive data")
encryptedMessage, nonce := crypto.EncryptWithAES(symmetricKey, plaintext)
fmt.Println("Encrypted Message:", encryptedMessage)
fmt.Println("Nonce:", nonce)

// Decrypt the message
decryptedMessage := crypto.DecryptWithAES(symmetricKey, []byte(encryptedMessage), nonce)
fmt.Println("Decrypted Message:", decryptedMessage)
```

## API Reference

### `NewCryptoUtils() *CryptoUtils`
Creates a new instance of the `CryptoUtils` struct.

---

### `GenerateRSAKeyPair() (string, string, error)`
Generates a new RSA key pair (private and public keys) in Base64-encoded PEM format.

---

### `EncryptWithPublicKey(publicKey *rsa.PublicKey, message []byte) string`
Encrypts a message using an RSA public key. Returns the Base64-encoded ciphertext.

---

### `DecryptWithPrivateKey(privateKeyString string, encryptedMessage string) []byte`
Decrypts a Base64-encoded message using an RSA private key.

---

### `Base64ToPrivateKey(base64PrivateKey string) (*rsa.PrivateKey, error)`
Converts a Base64-encoded PEM string into an RSA private key.

---

### `Base64ToPublicKey(base64PublicKey string) (*rsa.PublicKey, error)`
Converts a Base64-encoded PEM string into an RSA public key.

---

### `EncryptWithAES(key, plaintext []byte) (ciphertext string, nonce []byte)`
Encrypts plaintext using AES-GCM with the provided key. Returns a Base64-encoded ciphertext and a randomly generated nonce.

---

### `DecryptWithAES(key, ciphertext, nonce []byte) string`
Decrypts an AES-GCM-encrypted ciphertext using the provided key and nonce. Returns the plaintext.

## License

This package is licensed under the MIT License. See `LICENSE` for more information.

