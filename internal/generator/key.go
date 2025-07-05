package generator

import (
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"golang.org/x/crypto/chacha20"
)

// deterministicReader uses a seed to create an endless, deterministic
// stream of pseudo-random bytes, fulfilling the io.Reader interface.
// This is necessary because PGP key generation requires more random
// data than the seed length.
type deterministicReader struct {
	cipher *chacha20.Cipher
}

// Read fills the buffer 'p' with pseudo-random bytes from the cipher.
// It will never return an EOF.
func (r *deterministicReader) Read(p []byte) (n int, err error) {
	// Create a zero-filled slice of the same length as p.
	// When XORed with the keystream, this results in the keystream itself.
	plaintext := make([]byte, len(p))
	r.cipher.XORKeyStream(p, plaintext)
	return len(p), nil
}

// newDeterministicReader creates our custom reader seeded for determinism.
func newDeterministicReader(seed []byte) (io.Reader, error) {
	// ChaCha20 requires a 32-byte key. We use the first 32 bytes of our 64-byte BIP39 seed.
	key := seed[:32]

	// A 24-byte nonce. We use the next 24 bytes of the seed.
	// For determinism, this nonce must be the same every time for a given seed.
	nonce := seed[32:56]

	// Create the ChaCha20 cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("could not create chacha20 cipher: %w", err)
	}

	return &deterministicReader{cipher: cipher}, nil
}
func GeneratePGPKeyFromSeed(name, email string, seed []byte) (*openpgp.Entity, error) {
	// Instead of a reader with finite bytes, we create a PRNG stream from the seed.
	keyGenerator, err := newDeterministicReader(seed)
	if err != nil {
		return nil, err
	}

	pgpConfig := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		Rand:          keyGenerator, // Use our new endless reader
	}

	entity, err := openpgp.NewEntity(name, "Mnemonic-Generated Key", email, pgpConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating new entity: %w", err)
	}

	for id := range entity.Identities {
		err := entity.SignIdentity(id, entity, pgpConfig)
		if err != nil {
			return nil, fmt.Errorf("error self-signing identity %s: %w", id, err)
		}
	}

	return entity, nil
}

// saveKeys function remains the same
func SaveKeys(entity *openpgp.Entity) error {
	publicKeyFile, err := os.Create("public.asc")
	if err != nil {
		return fmt.Errorf("error creating public key file: %w", err)
	}
	defer publicKeyFile.Close()

	pubKeyWriter, err := armor.Encode(publicKeyFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("error creating armored public key writer: %w", err)
	}

	err = entity.Serialize(pubKeyWriter)
	if err != nil {
		return fmt.Errorf("error serializing public key: %w", err)
	}
	pubKeyWriter.Close()
	fmt.Println("✅ Public key saved to public.asc")

	privateKeyFile, err := os.Create("private.asc")
	if err != nil {
		return fmt.Errorf("error creating private key file: %w", err)
	}
	defer privateKeyFile.Close()

	privKeyWriter, err := armor.Encode(privateKeyFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("error creating armored private key writer: %w", err)
	}
	err = entity.SerializePrivate(privKeyWriter, nil)
	if err != nil {
		return fmt.Errorf("error serializing private key: %w", err)
	}
	privKeyWriter.Close()
	fmt.Println("✅ Private key saved to private.asc")

	return nil
}
