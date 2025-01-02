package crypto_utils_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sudhi001/crypto_utils"
)

func TestCryptoUtils_NewSession(t *testing.T) {
	crypto := crypto_utils.NewCryptoUtils()

	serverPublicKeyStr := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFuNzZQOWpJQm9aY2VlSzVSMjFCegp3eHpoVUR2OFk4TVNMVmxWWWdZZzQ3S3R3MXRxeHF0NHorVkl4MjBjNjViUUxYNk1GeVo0dHVmcmJ2alI2c2V0ClExV2l3c0d6UStNNkdaM2w5SmMxYzhyQ3RJV3JJdjF4M0pJTSs3djdiaEduTUdZeElGOGR1SHdJZkoxdmhFS04KY1kyWUd4b2xHaWVzZDRDREJYaWQxNWROL0R5dGFUUTNSYnQybnBlTHpqOHgyRjVYeFZlbzl4UU43TndVV3dWUwpGSHVqYk1jS2ZNM1pDaEM4T2l5cFV5QmpockMxdTJFc1IwV2pndjZkaFludTRrSHpHNnk0alVCTEF6RWI4Z1ZyCmlCRUJjME1UUWFQaTYvTGdYSjVVNzdqUWhmQ21nVkJ1a2xSZHlyQjJhTHkvTWRqbnM5TFdWekx2RG1iRzhEQ0YKZFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
	serverPublicKey, _ := crypto.Base64ToPublicKey(serverPublicKeyStr)
	serverPrivateKeyStr := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBbjc2UDlqSUJvWmNlZUs1UjIxQnp3eHpoVUR2OFk4TVNMVmxWWWdZZzQ3S3R3MXRxCnhxdDR6K1ZJeDIwYzY1YlFMWDZNRnlaNHR1ZnJidmpSNnNldFExV2l3c0d6UStNNkdaM2w5SmMxYzhyQ3RJV3IKSXYxeDNKSU0rN3Y3YmhHbk1HWXhJRjhkdUh3SWZKMXZoRUtOY1kyWUd4b2xHaWVzZDRDREJYaWQxNWROL0R5dAphVFEzUmJ0Mm5wZUx6ajh4MkY1WHhWZW85eFFON053VVd3VlNGSHVqYk1jS2ZNM1pDaEM4T2l5cFV5QmpockMxCnUyRXNSMFdqZ3Y2ZGhZbnU0a0h6RzZ5NGpVQkxBekViOGdWcmlCRUJjME1UUWFQaTYvTGdYSjVVNzdqUWhmQ20KZ1ZCdWtsUmR5ckIyYUx5L01kam5zOUxXVnpMdkRtYkc4RENGZFFJREFRQUJBb0lCQUdaVWJtZ3B0SDNORG9vRQpNUStxdzkxVEhNcUhBckR0ZnpGcHJwWnlrcE1LSE9HdUtBSklTY1h6Zk9HemRmazh6UEszeEFuNGJRL09GVFVyClUxMXd0LzhRVm9rb0NDd08zV01Ya1AxVDk3dkxRVnJlM2JnMlhzQUxGeUlUVTRjNDY3N0hWK1VDeVVrcXUwMEkKbFMxR2JORTNBUjhyYW1VTTBTQmtSSW8yci9Zd1JYaDJJczB4SjczRFhCQU8zeDNsWXZ1ckJadDJZOFQzWnhRMgp3QUhvSlZ6M3NZLzNSb3UvTzZRN0ptNFpoZjJCaGNxRmhOall3V1VLSlZlVXJNVWRLbENmSXdCRnR3YzI1UWlWCjUxbm8xc08rYkhTNGZNbnd4YUtQd2VQZ3BBUU1sbHRYakdIV3hCb1I2OENsVkJXOFF5ZFByWHdBTGdOQkpmR2sKOHpDSWtDa0NnWUVBelYrd0s4VU9jYUQvbVhRRDFWaFhSN1J4VHhQSEZmT1VIVDFLZERSM3Z6b3NvZnJTeFUxawpSbzVTTlJrSGFSYzhkem9WMzlJc3QyUHZob1NrSnhyMXFEQUx4TDEzSUFLS0FVdU00aEFXREhXRVdqSmV4QUxTCkFyZnhHWnZJclF3bnJVMkpLZ3ZnTzlFSDZ4SVpkbmpRRnd4eGhLK1prdERMN0RpaWxVcmM5MHNDZ1lFQXh4OWoKQWtrYlhRa01paUViZ1RXZWlqYjJuOHVnZ2F6ZzlPdUpRZ3RuaWltaW5id3lUb0k0K2Q2ZlIwY0FVbC8zMnVocgozSkZNK3czZ3R4QkV6UVR3eTlhQ2FCVG9xRTRpOEI1aWRIOEo5MUh2ZVZGRzhHN3lYaVBaOFVVTGd6K3pxVUJrCm5CTGd0MWQyMUV1Z2VLc05uY3RvSFJtNkRPRW4zZHBTZHNNU3ZqOENnWUI2U1dMTi9TMEhqZFVFRzJkNDdud3gKN3dpVkRISzc2R2ltTEd1YjIrMzlpSGN4RC9mV2thbUd0WkhQbWhLbWliWndTNzdnb2ZZTVVNNDc2OWtPaStnQQplSE5aZDNOcU5QalZvcFhGdWN4WEtOWmhHcU1BMWFrVkEwL2xiclJFRGZ2R0htZnhDRmRCWnNydk5yekFwVmxLCmtCYzc2WTlwTXpocGRLT2lmNHdwRndLQmdRREZyM3QwUVhCUkpUSzF6N2lteHJ6bkt6b2QydU0yMnBOYmxKdG8KWGpvbENNRFJLSTRwTTArdGdqOVBYRVlOZ2dsbjQyZHlTeTdKOERVd2lZNUVuS3NUTTV1MENVNFNDY0RWOHRSOApJOE9aTGxjNWNsK2pSQUtMUTd5VHM2Q0NaVFBReklVV0RnZmEvWktUb2FGbkt5c1JoV2VQdklMaFZvZGwwZUljCjFmNDlzUUtCZ0VCWkUyOEpOdkEzTFVzQVdZc1p6TVZEWmxDdjFvcmVsSVVCZVpSUGVQWXNnYWdvSWd0ckRRS0cKOExPdFZ3elRleXplTUlzclM1UFJSa3RoMVpnRDQxZjY3eHpDZTFXWEFVQ0RBQzhJWE5XdEVXWmI3czVHRGlUUwpqZnpoUkpYQVNwQm40ODZENEY4bmZxcmNianh3UVQxVEFWelE1VEZDZHNBcFEyODcxK2kyCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="

	// Client generates symmetric key and encrypts with server's public key
	symmetricKey := make([]byte, 32) // AES-256 key size
	_, err := rand.Read(symmetricKey)
	if err != nil {
		panic(err)
	}

	encryptedKey := crypto.EncryptWithPublicKey(serverPublicKey, symmetricKey)

	// 	// Simulate payload encryption on client
	payload := "{\"Code\":\"172\",\"Amount\":100.0,\"Currency\":\"INR\"}"
	encryptedPayload, nonce := crypto.EncryptWithAES(symmetricKey, []byte(payload))

	fmt.Println("Encrypted Key (to send to server):", encryptedKey)
	nonceString := base64.StdEncoding.EncodeToString(nonce)
	fmt.Println("Encrypted Nonce (to send to server):", nonceString)
	fmt.Println("Encrypted Payload (to send to server):", encryptedPayload)

	// Create the final JSON object
	result := map[string]interface{}{
		"payload": encryptedPayload,
		"nonce":   nonceString,
		"key":     encryptedKey,
	}

	// // Convert the result to a JSON string
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	// if err != nil {
	// 	panic(err)
	// }

	// // Print the JSON result
	fmt.Println(string(resultJSON))

	// 	// Server decrypts the symmetric key
	decryptedSymmetricKey := crypto.DecryptWithPrivateKey(serverPrivateKeyStr, encryptedKey)

	// 	// Server decrypts the payload
	decryptedPayload := crypto.DecryptWithAES(decryptedSymmetricKey, []byte(encryptedPayload), nonce)

	fmt.Println("Decrypted Payload on Server:", decryptedPayload)
}
