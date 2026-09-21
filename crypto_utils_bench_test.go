package crypto_utils_test

import (
	"testing"

	"github.com/sudhi001/crypto_utils"
)

// Benchmarks exercise the public string-based API, so RSA numbers include
// base64 + PEM parsing of the key on every call, exactly as a caller pays it.
// Run with: go test -bench . -benchmem -run ^$

var (
	benchPriv, benchPub = mustBenchKeyPair()
	benchAESKey         = mustRandom(32)
	bench1KiB           = mustRandom(1024)
	bench1MiB           = mustRandom(1024 * 1024)
)

func mustBenchKeyPair() (string, string) {
	priv, pub, err := crypto_utils.NewCryptoUtils().GenerateRSAKeyPair()
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func mustRandom(n int) []byte {
	b, err := crypto_utils.NewCryptoUtils().GenerateRandomBytes(n)
	if err != nil {
		panic(err)
	}
	return b
}

func BenchmarkRsaKeygen2048(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.GenerateRSAKeyPair(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRsaPkcs1Encrypt32b(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	for i := 0; i < b.N; i++ {
		if _, err := c.EncryptRSA(benchPub, benchAESKey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRsaPkcs1Decrypt32b(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	ct, _ := c.EncryptRSA(benchPub, benchAESKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.DecryptWithPrivateKey(benchPriv, ct); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRsaOaepEncrypt32b(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	for i := 0; i < b.N; i++ {
		if _, err := c.EncryptWithPublicKeyOAEP(benchPub, benchAESKey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRsaOaepDecrypt32b(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	ct, _ := c.EncryptWithPublicKeyOAEP(benchPub, benchAESKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.DecryptWithPrivateKeyOAEP(benchPriv, ct); err != nil {
			b.Fatal(err)
		}
	}
}

func benchAESEncrypt(b *testing.B, plaintext []byte) {
	c := crypto_utils.NewCryptoUtils()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		if _, _, err := c.EncryptAESGCM(benchAESKey, plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func benchAESDecrypt(b *testing.B, plaintext []byte) {
	c := crypto_utils.NewCryptoUtils()
	ct, nonce, _ := c.EncryptAESGCM(benchAESKey, plaintext)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.DecryptAESGCM(benchAESKey, ct, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAesGcmEncrypt1kib(b *testing.B) { benchAESEncrypt(b, bench1KiB) }
func BenchmarkAesGcmDecrypt1kib(b *testing.B) { benchAESDecrypt(b, bench1KiB) }
func BenchmarkAesGcmEncrypt1mib(b *testing.B) { benchAESEncrypt(b, bench1MiB) }
func BenchmarkAesGcmDecrypt1mib(b *testing.B) { benchAESDecrypt(b, bench1MiB) }

func BenchmarkSignSha256_1kib(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	for i := 0; i < b.N; i++ {
		if _, err := c.Sign(benchPriv, bench1KiB); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifySha256_1kib(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	sig, _ := c.Sign(benchPriv, bench1KiB)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, err := c.Verify(benchPub, bench1KiB, sig); err != nil || !ok {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkEnvelopeEncryptSigned1kib(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	for i := 0; i < b.N; i++ {
		if _, err := c.EncryptPayloadSigned(benchPub, benchPriv, bench1KiB); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnvelopeDecryptVerified1kib(b *testing.B) {
	c := crypto_utils.NewCryptoUtils()
	env, _ := c.EncryptPayloadSigned(benchPub, benchPriv, bench1KiB)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.DecryptPayloadVerified(benchPriv, benchPub, env); err != nil {
			b.Fatal(err)
		}
	}
}
