package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/thisismz/kilid/internal/generator"
	"github.com/thisismz/kilid/internal/sezar"
)

func main() {
	userName := "thisismz"
	userEmail := "mahdimozaffari@outlook.com"
	bip39Passphrase := "my-super-secret-passphrase"

	seed, mnemonic, err := generator.GenerateBipSeed(256, bip39Passphrase)
	if err != nil {
		log.Fatalf("Failed to generate mnemonic: %v", err)
	}
	fmt.Println("======================================================================")
	fmt.Println("✅ Your New Mnemonic Seed Phrase:")
	fmt.Println(mnemonic)
	fmt.Println("======================================================================")
	fmt.Println("🔴 IMPORTANT: Write this phrase down and store it in a safe place.")
	fmt.Println("======================================================================")

	fmt.Println("\n⚙️  Generating PGP key pair from the seed (using ProtonMail/go-crypto)...")
	entity, err := generator.GeneratePGPKeyFromSeed(userName, userEmail, seed)
	if err != nil {
		log.Fatalf("Failed to generate PGP key: %v", err)
	}
	fmt.Println("✅ PGP Key pair generated successfully!")

	err = generator.SaveKeys(entity)
	if err != nil {
		log.Fatalf("Failed to save keys: %v", err)
	}

	// Load the keys we just saved (simulating a real application)
	publicKeyBytes, err := os.ReadFile("public.asc")
	if err != nil {
		log.Fatalf("Failed to read public key file: %v", err)
	}
	privateKeyBytes, err := os.ReadFile("private.asc")
	if err != nil {
		log.Fatalf("Failed to read private key file: %v", err)
	}

	// The original message we want to protect
	originalMessage := []byte("This message is a secret and was generated deterministically!")
	fmt.Printf("Original Message:  %s\n", originalMessage)

	// Encrypt the message using the public key
	encryptedBytes, err := sezar.EncryptBytes(publicKeyBytes, originalMessage)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	// We encode to Base64 just for clean printing
	fmt.Printf("Encrypted (Base64):\n%s\n", base64.StdEncoding.EncodeToString(encryptedBytes))

	// Decrypt the message using the private key
	decryptedBytes, err := sezar.DecryptBytes(privateKeyBytes, encryptedBytes)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted Message: %s\n", decryptedBytes)

	// --- Verification ---
	fmt.Println("\n--- Verification ---")
	if bytes.Equal(originalMessage, decryptedBytes) {
		fmt.Println("✅ SUCCESS: Decrypted message matches the original.")
	} else {
		fmt.Println("❌ FAILED: Decrypted message does NOT match the original.")
	}
}
