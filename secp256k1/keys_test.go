package secp256k1

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

func TestECDSA_SignAndVerify(t *testing.T) {
	kp := GenerateKeypair()

	msg := [32]byte{1, 2, 3}
	sig, err := kp.Sign(msg[:])
	require.NoError(t, err)

	msg = [32]byte{1, 2, 3}
	ok, err := kp.Public().Verify(msg[:], sig)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestECDSA_SignAndRecover(t *testing.T) {
	kp := GenerateKeypair()

	msg := [32]byte{1, 2, 3}
	sig, err := kp.Sign(msg[:])
	require.NoError(t, err)

	ethSig, err := sig.EncodeRecoverable()
	require.NoError(t, err)

	pubKey, err := kp.Public().Encode()
	require.NoError(t, err)
	require.Equal(t, 33, len(pubKey))

	recKey, err := secp256k1.RecoverPubkey(msg[:], ethSig)
	require.NoError(t, err)

	pubKey, err = kp.Public().EncodeDecompressed()
	require.NoError(t, err)

	require.Equal(t, recKey[1:65], pubKey)
}
