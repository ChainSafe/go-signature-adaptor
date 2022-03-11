package secp256k1

import (
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSignature_EthereumCompatibility(t *testing.T) {
	kp := GenerateKeypair()

	msg := [32]byte{1, 2, 3}
	sig, err := kp.Sign(msg[:])
	require.NoError(t, err)

	msg = [32]byte{1, 2, 3}
	priv, err := kp.private.Encode()
	require.NoError(t, err)
	ethSig, err := secp256k1.Sign(msg[:], priv)
	require.NoError(t, err)

	// Our verify with eth sig WORKS NICE
	newSig := &Signature{}
	err = newSig.Decode(ethSig)
	require.NoError(t, err)
	ok, err := kp.Public().Verify(msg[:], newSig)
	require.NoError(t, err)
	assert.True(t, ok)

	// Eth verify with our sig
	msg = [32]byte{1, 2, 3}
	encSig, err := sig.Encode()
	require.NoError(t, err)
	require.Equal(t, len(encSig), 64)
	pubKey, err := kp.Public().Encode()
	require.NoError(t, err)

	verified := secp256k1.VerifySignature(pubKey, msg[:], encSig[:])
	assert.True(t, verified)
}
