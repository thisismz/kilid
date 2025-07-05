package sezar

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// decryptBytes takes an armored private key and ciphertext,
// returning the decrypted plaintext.
func DecryptBytes(privateKeyBytes []byte, ciphertext []byte) ([]byte, error) {
	// 1. Read the private key
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("could not read private key ring: %w", err)
	}
	if len(entityList) == 0 {
		return nil, fmt.Errorf("no private key found in the provided data")
	}

	// NOTE: Our private key is not password-protected. If it were, we would need to
	// call entity.PrivateKey.Decrypt(passphrase) here for each entity.

	// 2. Create a ciphertext reader
	ciphertextReader := bytes.NewReader(ciphertext)

	// 3. Decrypt the message
	// The keyring holds the private keys that can be used for decryption.
	md, err := openpgp.ReadMessage(ciphertextReader, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("could not read PGP message: %w", err)
	}

	// 4. Read the decrypted plaintext
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("could not read decrypted plaintext: %w", err)
	}

	// Check for signature errors, though we didn't sign in this example
	if md.SignatureError != nil {
		return nil, fmt.Errorf("signature error on PGP message: %w", md.SignatureError)
	}

	return plaintext, nil
}
