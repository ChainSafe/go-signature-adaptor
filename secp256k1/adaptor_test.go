package secp256k1

import (
	"encoding/hex"
	"testing"

	"github.com/renproject/secp256k1"

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

func TestRecoverFromAdaptorAndSignature(t *testing.T) {
	kp := GenerateKeypair()

	msg := [32]byte{1, 2, 3}
	sig, err := kp.AdaptorSign(msg[:])
	require.NoError(t, err)

	ok, err := kp.Public().VerifyAdaptor(msg[:], sig.AdaptorWithSecret.adaptor)
	require.NoError(t, err)
	require.True(t, ok)

	// TODO: fix this, doesn't work with signatures we generated
	secret, err := RecoverFromAdaptorAndSignature(sig.AdaptorWithSecret.adaptor, sig.Signature)
	require.NoError(t, err)
	require.True(t, secret.Eq(sig.AdaptorWithSecret.secret))
}

func TestAdaptor_ValidPlain(t *testing.T) {
	adaptorStr, err := hex.DecodeString("03424d14a5471c048ab87b3b83f6085d125d5864249ae4297a57c84e74710bb6730223f325042fce535d040fee52ec13231bf709ccd84233c6944b90317e62528b2527dff9d659a96db4c99f9750168308633c1867b70f3a18fb0f4539a1aecedcd1fc0148fc22f36b6303083ece3f872b18e35d368b3958efe5fb081f7716736ccb598d269aa3084d57e1855e1ea9a45efc10463bbf32ae378029f5763ceb40173f")
	require.NoError(t, err)
	messageHashStr, err := hex.DecodeString("8131e6f4b45754f2c90bd06688ceeabc0c45055460729928b4eecf11026a9e2d")
	require.NoError(t, err)

	pubkeyStr, err := hex.DecodeString("035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c")
	require.NoError(t, err)
	pubkey := &PublicKey{}
	pubkey.Decode(pubkeyStr)

	encryptionkeyStr, err := hex.DecodeString("02c2662c97488b07b6e819124b8989849206334a4c2fbdf691f7b34d2b16e9c293")
	require.NoError(t, err)

	decryptionKeyStr, err := hex.DecodeString("0b2aba63b885a0f0e96fa0f303920c7fb7431ddfa94376ad94d969fbf4109dc8")
	require.NoError(t, err)
	y := &secp256k1.Fn{}
	y.SetB32(decryptionKeyStr)

	// verify ecdsa signature
	signatureStr, err := hex.DecodeString("424d14a5471c048ab87b3b83f6085d125d5864249ae4297a57c84e74710bb67329e80e0ee60e57af3e625bbae1672b1ecaa58effe613426b024fa1621d903394")
	require.NoError(t, err)
	sig := &Signature{}
	err = sig.Decode(signatureStr)
	require.NoError(t, err)
	ok, err := pubkey.Verify(messageHashStr, sig)
	require.NoError(t, err)
	require.True(t, ok)

	// verify adaptor signature
	adaptor := &Adaptor{}
	err = adaptor.Decode(adaptorStr)
	require.NoError(t, err)

	Y := &secp256k1.Point{}
	Y.SetBytes(encryptionkeyStr)
	adaptor.proof.Y = Y

	// recover decryption key
	secret, err := RecoverFromAdaptorAndSignature(adaptor, sig)
	require.NoError(t, err)
	require.True(t, secret.Eq(y))

	// TODO: dleq check fails, probably due to hash issues
	ok, err = pubkey.VerifyAdaptor(messageHashStr, adaptor)
	require.NoError(t, err)
	require.True(t, ok)
}
