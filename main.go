package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/thisismz/kilid/internal/generator"
	"github.com/thisismz/kilid/internal/sezar"
)

var (
	// CLI Flags
	save          = flag.Bool("save", false, "Save the mnemonic seed phrase to a local file")
	outputDir     = flag.String("output", ".", "Directory to save the mnemonic file")
	inputFile     = flag.String("input", "test.txt", "File to encrypt")
	encryptedFile = flag.String("encrypted", "encrypted.txt", "File to write encrypted data")
	decryptedFile = flag.String("decrypted", "decrypted.txt", "File to write decrypted data")
	encrypt       = flag.Bool("encrypt", false, "Encrypt the file")
	decrypt       = flag.Bool("decrypt", false, "Decrypt the file")
	email         = flag.String("user-email", "mahdimozaffari@outlook.com", "User email")
	username      = flag.String("user-name", "thisismz", "User name")
	passphrase    = flag.String("bip39-passphrase", "my-super-secret-passphrase", "BIP39 passphrase")
	seed          = flag.String("seed", "", "Seed phrase")
)

func main() {

	flag.Parse()

	switch {
	case *save:
		handleSave(*username, *email, *passphrase, *outputDir)
	case *encrypt && *decrypt:
		log.Fatal("Cannot encrypt and decrypt at the same time")
	case *encrypt || *decrypt:
		handleEncryptDecrypt(*username, *email, *seed, *inputFile, *encryptedFile, *decryptedFile, *encrypt, *decrypt)
	default:
		log.Fatal("Either --encrypt or --decrypt or --save must be specified")
	}
}

func handleSave(username, email, passphrase, outputDir string) {
	seedBytes, mnemonic, err := generator.GenerateBipSeed(256, passphrase)
	if err != nil {
		log.Fatalf("❌ Failed to generate mnemonic: %v", err)
	}

	fmt.Println("✅ Mnemonic:", mnemonic)
	log.Println("⚙️  Generating PGP key pair...")

	entity, err := generator.GeneratePGPKeyFromSeed(username, email, seedBytes)
	if err != nil {
		log.Fatalf("❌ Failed to generate PGP key: %v", err)
	}

	if err := generator.SaveKeys(entity, outputDir); err != nil {
		log.Fatalf("❌ Failed to save keys: %v", err)
	}

	log.Println("✅ PGP key pair generated and saved to", outputDir)
}

func handleEncryptDecrypt(username, email, seed, inputFile, encryptedFile, decryptedFile string, encrypt, decrypt bool) {
	if seed == "" {
		log.Fatal("❌ Seed is required for encryption or decryption")
	}
	if inputFile == "" {
		log.Fatal("❌ Input file is required")
	}

	entity, err := generator.GeneratePGPKeyFromSeed(username, email, []byte(seed))
	if err != nil {
		log.Fatalf("❌ Failed to generate PGP key from seed: %v", err)
	}

	pubKey, privKey, err := generator.GetKeysAsBytes(entity)
	if err != nil {
		log.Fatalf("❌ Failed to extract key bytes: %v", err)
	}

	switch {
	case encrypt:
		if err := sezar.EncryptBytes(pubKey, inputFile, encryptedFile); err != nil {
			log.Fatalf("❌ Encryption failed: %v", err)
		}
		log.Println("✅ File encrypted:", encryptedFile)

	case decrypt:
		if err := sezar.DecryptBytes(privKey, encryptedFile, decryptedFile); err != nil {
			log.Fatalf("❌ Decryption failed: %v", err)
		}
		log.Println("✅ File decrypted:", decryptedFile)
	}
}
