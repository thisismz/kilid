package sezar

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func EncryptBytes(publicKeyBytes []byte, inputPath string, outputPath string) error {
	fmt.Println("🔐 Encrypting file...")

	// Check file info early
	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("failed to stat input file: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("input file is empty")
	}

	// Open input file for reading
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	// Create output file for writing encrypted data
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %w", err)
	}
	defer outFile.Close()

	// Load public key
	keyRing, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicKeyBytes))
	if err != nil {
		return fmt.Errorf("failed to read public key ring: %w", err)
	}
	if len(keyRing) == 0 {
		return fmt.Errorf("no keys found in public key ring")
	}

	// Create encryption writer
	encryptWriter, err := openpgp.Encrypt(outFile, keyRing, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create encryption writer: %w", err)
	}

	// Stream file into encryption writer
	if _, err := io.Copy(encryptWriter, inFile); err != nil {
		return fmt.Errorf("failed to encrypt input file: %w", err)
	}

	// Close the writer to finalize encryption
	if err := encryptWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize encryption: %w", err)
	}

	fmt.Println("✅ Encryption complete:", outputPath)
	return nil
}
