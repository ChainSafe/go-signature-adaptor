package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeterministicNonce(t *testing.T) {
	alice := KeypairFromHex("36f2152e1e5c9b533d170bff48188d0b13af2c009cac88c336183530ac628cba")
	oneTime := KeypairFromHex("2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6")

	msg := [32]byte{1, 2, 3}

	nonceFn := WithRFC6979(alice.Private(), msg[:], oneTime.Public())
	k, err := nonceFn()
	require.NoError(t, err)

	require.Equal(t, *scalarFromHex("673a490405336ae50887649f0988077e1e7e46585c289aafd91586d4e7420874"), *k)
}
