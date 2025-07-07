package sezar

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func DecryptBytes(privateKeyBytes []byte, inputPath string, outputPath string) error {
	fmt.Println("🔓 Decrypting file...")

	// 1. Load encrypted file
	encryptedData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}
	if len(encryptedData) == 0 {
		return fmt.Errorf("encrypted file is empty")
	}

	// 2. Parse private key ring
	keyRing, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateKeyBytes))
	if err != nil {
		return fmt.Errorf("failed to read private key ring: %w", err)
	}
	if len(keyRing) == 0 {
		return fmt.Errorf("no keys found in private key ring")
	}

	// 3. Decrypt message
	md, err := openpgp.ReadMessage(bytes.NewReader(encryptedData), keyRing, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt message: %w", err)
	}
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return fmt.Errorf("failed to read decrypted content: %w", err)
	}
	if md.SignatureError != nil {
		return fmt.Errorf("PGP signature verification failed: %w", md.SignatureError)
	}

	// 4. Write decrypted content
	if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	fmt.Println("✅ Decryption complete:", outputPath)
	return nil
}
