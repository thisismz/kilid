package sezar

import (
	"bytes"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// encryptBytes takes an armored public key and a plaintext message,
// returning the encrypted ciphertext.
func EncryptBytes(publicKeyBytes []byte, plaintext []byte) ([]byte, error) {
	// 1. Read the public key
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("could not read public key ring: %w", err)
	}
	if len(entityList) == 0 {
		return nil, fmt.Errorf("no public key found in the provided data")
	}

	// 2. Create a buffer to hold the encrypted data
	encryptedBuf := new(bytes.Buffer)

	// 3. Create an encryption writer
	// The `to` argument takes the entities to encrypt for. `signed` can be nil for no signature.
	plaintextWriter, err := openpgp.Encrypt(encryptedBuf, entityList, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create encryption writer: %w", err)
	}

	// 4. Write the plaintext to the encryption writer
	_, err = plaintextWriter.Write(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to write plaintext: %w", err)
	}

	// 5. IMPORTANT: Close the writer to finalize the encryption
	err = plaintextWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close encryption writer: %w", err)
	}

	return encryptedBuf.Bytes(), nil
}
