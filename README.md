# go-signature-adaptor

Pure Go implementation of signature adaptors using ECDSA. Currently implemented for secp256k1 but generalized to be extended over any curve. It is based off the [DLC spec](https://github.com/discreetlogcontracts/dlcspecs/blob/master/ECDSA-adaptor.md).

Adaptor signatures are a kind of signature encryption. Just as you would expect this means you can’t get the signature from the encrypted signature unless you know the decryption key. As you might not necessarily expect, this encryption is one-time in that anyone who knows the encrypted signature can recover the decryption key from the decrypted signature.

This weird leaking of the decryption key is incredibly useful has numerous applications in blockchain space and cryptography more generally.

## Example
```go
package main

import (
	"fmt"
	"github.com/ChainSafe/go-signature-adaptor/secp256k1"
)

func main() {
	msg := []byte{1, 2, 3}
	alice := secp256k1.GenerateKeypair()
	bob := secp256k1.GenerateKeypair()

	adaptor, _ := alice.AdaptorSign(msg, bob.Public())

	ok, _ := alice.Public().VerifyAdaptor(msg[:], bob.Public(), adaptor)
	if !ok {
		panic("Alice sent invalid adaptor")
	}

	sig, _ := adaptor.Decrypt(bob.Private().Inner())
	sigBytes, _ := sig.EncodeRecoverable()
	fmt.Println("Posting decrypted ECDSA signature on-chain", sigBytes, "🚀")
}
```

## Requirements

go 1.17+
