package secp256k1

import (
	"testing"

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
