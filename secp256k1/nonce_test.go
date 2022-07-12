package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeterministicNonce(t *testing.T) {
	alice := GenerateKeypair()
	msg := [32]byte{1, 2, 3}

	k, err := nonceRFC6979(alice.Private(), msg[:])
	require.NoError(t, err)

	require.Equal(t, *scalarFromHex("a969e6f8e825705b3dbd76a7831cb8650ed498dab4c014ae77103937222f94f1"), *k)
}
