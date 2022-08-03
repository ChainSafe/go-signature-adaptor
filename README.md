# go-signature-adaptor

Pure Go implementation of signature adaptors using ECDSA. Currently implemented for secp256k1 but generalized to be extended over any curve. It is based off the [DLC spec](https://github.com/discreetlogcontracts/dlcspecs/blob/master/ECDSA-adaptor.md).

Adaptor signatures are a kind of signature encryption. Just as you would expect this means you can’t get the signature from the encrypted signature unless you know the decryption key. As you might not necessarily expect, this encryption is one-time in that anyone who knows the encrypted signature can recover the decryption key from the decrypted signature.

This weird leaking of the decryption key is incredibly useful has numerous applications in blockchain space and cryptography more generally.

## Requirements

go 1.17+
