// Command interop is a tiny CLI used by the cross-language interoperability
// test-suite (see ../../../interop). Every implementation (Go, Dart, Rust)
// exposes the same sub-commands so their outputs can be fed into each other.
//
//	keygen      <priv_out> <pub_out>
//	encrypt     <recipient_pub> <sender_priv|-> <in> <out_json> [pkcs1|oaep]
//	decrypt     <recipient_priv> <sender_pub|-> <in_json> <out> [pkcs1|oaep]
//	rsa-encrypt <pub> <in> <out_b64> [pkcs1|oaep]
//	rsa-decrypt <priv> <in_b64> <out> [pkcs1|oaep]
//	sign        <priv> <in> <out_b64>
//	verify      <pub> <in> <sig_b64>
//	aes-encrypt <key_b64_file> <in> <out_json>
//	aes-decrypt <key_b64_file> <in_json> <out>
//	keygen-v2   <x25519_priv_out> <x25519_pub_out> <ed25519_priv_out> <ed25519_pub_out>
//	encrypt-v2  <recipient_x25519_pub> <sender_ed25519_priv|-> <in> <out_json>
//	decrypt-v2  <recipient_x25519_priv> <sender_ed25519_pub|-> <in_json> <out>
//
// Key files hold the base64(PEM) string used throughout the libraries. Passing
// "-" as the sender key skips signing (encrypt) or signature verification (decrypt).
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sudhi001/crypto_utils"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing sub-command")
	}
	c := crypto_utils.NewCryptoUtils()
	cmd, args := args[0], args[1:]

	switch cmd {
	case "keygen":
		need(args, 2)
		priv, pub, err := c.GenerateRSAKeyPair()
		if err != nil {
			return err
		}
		if err := os.WriteFile(args[0], []byte(priv), 0o600); err != nil {
			return err
		}
		return os.WriteFile(args[1], []byte(pub), 0o644)

	case "encrypt":
		need(args, 4)
		pub, priv, payload := readKey(args[0]), optionalKey(args[1]), readFile(args[2])
		var env *crypto_utils.Envelope
		var err error
		switch {
		case mode(args, 4) == "oaep" && priv == "":
			env, err = c.EncryptPayloadOAEP(pub, payload)
		case mode(args, 4) == "oaep":
			env, err = c.EncryptPayloadSignedOAEP(pub, priv, payload)
		case priv == "":
			env, err = c.EncryptPayload(pub, payload)
		default:
			env, err = c.EncryptPayloadSigned(pub, priv, payload)
		}
		if err != nil {
			return err
		}
		data, _ := json.MarshalIndent(env, "", "  ")
		return os.WriteFile(args[3], data, 0o644)

	case "decrypt":
		need(args, 4)
		priv, pub := readKey(args[0]), optionalKey(args[1])
		var env crypto_utils.Envelope
		if err := json.Unmarshal(readFile(args[2]), &env); err != nil {
			return err
		}
		var plaintext []byte
		var err error
		switch {
		case mode(args, 4) == "oaep" && pub == "":
			plaintext, err = c.DecryptPayloadOAEP(priv, &env)
		case mode(args, 4) == "oaep":
			plaintext, err = c.DecryptPayloadVerifiedOAEP(priv, pub, &env)
		case pub == "":
			plaintext, err = c.DecryptPayload(priv, &env)
		default:
			plaintext, err = c.DecryptPayloadVerified(priv, pub, &env)
		}
		if err != nil {
			return err
		}
		return os.WriteFile(args[3], plaintext, 0o644)

	case "rsa-encrypt":
		need(args, 3)
		var out string
		var err error
		if mode(args, 3) == "oaep" {
			out, err = c.EncryptWithPublicKeyOAEP(readKey(args[0]), readFile(args[1]))
		} else {
			out, err = c.EncryptRSA(readKey(args[0]), readFile(args[1]))
		}
		if err != nil {
			return err
		}
		return os.WriteFile(args[2], []byte(out), 0o644)

	case "rsa-decrypt":
		need(args, 3)
		var out []byte
		var err error
		if mode(args, 3) == "oaep" {
			out, err = c.DecryptWithPrivateKeyOAEP(readKey(args[0]), readKey(args[1]))
		} else {
			out, err = c.DecryptWithPrivateKey(readKey(args[0]), readKey(args[1]))
		}
		if err != nil {
			return err
		}
		return os.WriteFile(args[2], out, 0o644)

	case "sign":
		need(args, 3)
		sig, err := c.Sign(readKey(args[0]), readFile(args[1]))
		if err != nil {
			return err
		}
		return os.WriteFile(args[2], []byte(sig), 0o644)

	case "verify":
		need(args, 3)
		ok, err := c.Verify(readKey(args[0]), readFile(args[1]), readKey(args[2]))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("signature verification failed")
		}
		return nil

	case "aes-encrypt":
		need(args, 3)
		key := decodeB64(readKey(args[0]))
		ciphertext, nonce, err := c.EncryptAESGCM(key, readFile(args[1]))
		if err != nil {
			return err
		}
		data, _ := json.MarshalIndent(map[string]string{"ciphertext": ciphertext, "nonce": nonce}, "", "  ")
		return os.WriteFile(args[2], data, 0o644)

	case "aes-decrypt":
		need(args, 3)
		key := decodeB64(readKey(args[0]))
		var in struct{ Ciphertext, Nonce string }
		if err := json.Unmarshal(readFile(args[1]), &in); err != nil {
			return err
		}
		plaintext, err := c.DecryptAESGCM(key, in.Ciphertext, in.Nonce)
		if err != nil {
			return err
		}
		return os.WriteFile(args[2], plaintext, 0o644)

	case "keygen-v2":
		need(args, 4)
		xPriv, xPub, err := c.GenerateX25519KeyPair()
		if err != nil {
			return err
		}
		edPriv, edPub, err := c.GenerateEd25519KeyPair()
		if err != nil {
			return err
		}
		for i, v := range []string{xPriv, xPub, edPriv, edPub} {
			if err := os.WriteFile(args[i], []byte(v), 0o600); err != nil {
				return err
			}
		}
		return nil

	case "encrypt-v2":
		need(args, 4)
		env, err := c.EncryptPayloadV2(readKey(args[0]), optionalKey(args[1]), readFile(args[2]))
		if err != nil {
			return err
		}
		data, _ := json.MarshalIndent(env, "", "  ")
		return os.WriteFile(args[3], data, 0o644)

	case "decrypt-v2":
		need(args, 4)
		var env crypto_utils.EnvelopeV2
		if err := json.Unmarshal(readFile(args[2]), &env); err != nil {
			return err
		}
		plaintext, err := c.DecryptPayloadV2(readKey(args[0]), optionalKey(args[1]), &env)
		if err != nil {
			return err
		}
		return os.WriteFile(args[3], plaintext, 0o644)

	default:
		return fmt.Errorf("unknown sub-command %q", cmd)
	}
}

func need(args []string, n int) {
	if len(args) < n {
		fmt.Fprintf(os.Stderr, "error: expected at least %d arguments, got %d\n", n, len(args))
		os.Exit(2)
	}
}

func mode(args []string, i int) string {
	if len(args) > i {
		return args[i]
	}
	return "pkcs1"
}

func readFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	return data
}

// readKey reads a single-line base64 string, tolerating a trailing newline.
func readKey(path string) string {
	return strings.TrimSpace(string(readFile(path)))
}

// optionalKey returns "" when path is "-", otherwise the key file's contents.
func optionalKey(path string) string {
	if path == "-" {
		return ""
	}
	return readKey(path)
}

func decodeB64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	return data
}
