package generator

import (
	"log"

	"github.com/tyler-smith/go-bip39"
)

func GenerateBipSeed(entropy int, passphrase string) ([]byte, string, error) {
	ent, err := bip39.NewEntropy(entropy)
	if err != nil {
		log.Fatalf("Failed to generate entropy: %v", err)
	}
	mnemonic, err := bip39.NewMnemonic(ent)
	if err != nil {
		log.Fatalf("Failed to generate mnemonic: %v", err)
	}
	seed := bip39.NewSeed(mnemonic, passphrase)
	return seed, mnemonic, nil
}
