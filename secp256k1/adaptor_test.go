package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdaptor_SignAndVerify(t *testing.T) {
	kp := GenerateKeypair()

	msg := [32]byte{1, 2, 3}
	sig, err := kp.AdaptorSign(msg[:])
	require.NoError(t, err)

	ok, err := kp.Public().VerifyAdaptor(msg[:], sig.AdaptorWithSecret.adaptor)
	require.NoError(t, err)
	require.True(t, ok)
}
