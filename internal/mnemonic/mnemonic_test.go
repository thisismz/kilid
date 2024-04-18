// Package melt provides function to create a mnemonic set of keys from a

// ed25519 private key, and restore that key from the same mnemonic set of

// words.

package mnemonic

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/matryer/is"
)

func TestToMnemonic(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		is := is.New(t)
		w, err := toMnemonic([]byte{})
		is.Equal(w, "")
		is.True(err != nil)
	})

	t.Run("valid", func(t *testing.T) {
		is := is.New(t)
		_, k, err := ed25519.GenerateKey(rand.Reader)
		is.NoErr(err)
		w, err := ToMnemonic(&k)
		is.NoErr(err)
		is.True(w != "")
	})
}

func TestFromMnemonic(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		is := is.New(t)
		key, err := FromMnemonic("nope nope nope")
		is.Equal(key, nil)
		is.True(err != nil)
	})

	t.Run("valid", func(t *testing.T) {
		is := is.New(t)
		key, err := FromMnemonic(`
			alter gap broom kitten orient over settle work honey rule
			coach system wage effort mask void solid devote divert
			quarter quote broccoli jaguar lady
		`)
		is.NoErr(err)
		is.True(key != nil)
	})
}

// benchmark
func BenchmarkToMnemonic(b *testing.B) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ToMnemonic(&k)
	}
}
func BenchmarkFromMnemonic(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FromMnemonic(`
			alter gap broom kitten orient over settle work honey rule
			coach system wage effort mask void solid devote divert
			quarter quote broccoli jaguar lady
		`)
	}
}
