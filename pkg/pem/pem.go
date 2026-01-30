package pem

import (
	"bytes"
	"encoding/pem"
)

var pemHeader = []byte("-----BEGIN")

func IsPEM(data []byte) bool {
	return bytes.Contains(data, pemHeader)
}

type BlockType string

const (
	TypeCertificate     BlockType = "CERTIFICATE"
	TypePrivateKey      BlockType = "PRIVATE KEY"
	TypeECPrivateKey    BlockType = "EC PRIVATE KEY"
	TypeRSAPrivateKey   BlockType = "RSA PRIVATE KEY"
	TypePublicKey       BlockType = "PUBLIC KEY"
	TypeRSAPublicKey    BlockType = "RSA PUBLIC KEY"
	TypeECPublicKey     BlockType = "EC PUBLIC KEY"
	TypeMLKEMPrivateKey BlockType = "ML-KEM PRIVATE KEY"
	TypeMLKEMPublicKey  BlockType = "ML-KEM PUBLIC KEY"
	TypePQCCertificate  BlockType = "POST-QUANTUM CERTIFICATE"
)

func FindBlock(data []byte, types ...BlockType) ([]byte, bool) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, false
		}

		for _, t := range types {
			if block.Type == string(t) {
				return block.Bytes, true
			}
		}
		data = rest
	}
}
