module github.com/noot/go-signature-adaptor

go 1.17

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/ethereum/go-ethereum v1.10.16
	github.com/renproject/secp256k1 v0.0.0-20210503051125-8f6a00917811
	github.com/stretchr/testify v1.7.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/renproject/surge v1.2.3 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace github.com/renproject/secp256k1 v0.0.0-20210503051125-8f6a00917811 => ../secp256k1
