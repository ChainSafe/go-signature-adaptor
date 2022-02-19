package secp256k1

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
	"testing"
)

func TestSignature_EthereumCompatibility(t *testing.T) {
	kp := GenerateKeypair()

	msg := [32]byte{1, 2, 3}
	sig, err := kp.Sign(msg[:])
	require.NoError(t, err)

	//ethSig, err := secp256k1.Sign(msg[:], kp.private.Encode())
	ethSig, err := secp256k1.Sign(msg[:], kp.private.Encode())
	require.NoError(t, err)
	//fmt.Println(sig.r)
	b, err := sig.Encode()
	require.NoError(t, err)
	fmt.Println(b)
	fmt.Println(ethSig)
	assert.Equal(t, b, ethSig)
}
