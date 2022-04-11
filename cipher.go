package pkcs8

import (
	"crypto/cipher"
	"encoding/asn1"

	"github.com/emmansun/gmsm/padding"
)

type cipherWithBlock struct {
	oid      asn1.ObjectIdentifier
	ivSize   int
	keySize  int
	newBlock func(key []byte) (cipher.Block, error)
}

func (c cipherWithBlock) IVSize() int {
	return c.ivSize
}

func (c cipherWithBlock) KeySize() int {
	return c.keySize
}

func (c cipherWithBlock) OID() asn1.ObjectIdentifier {
	return c.oid
}

func (c cipherWithBlock) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	return cbcEncrypt(block, key, iv, plaintext)
}

func (c cipherWithBlock) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	return cbcDecrypt(block, key, iv, ciphertext)
}

func cbcEncrypt(block cipher.Block, key, iv, plaintext []byte) ([]byte, error) {
	mode := cipher.NewCBCEncrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plainText := pkcs7.Pad(plaintext)
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)
	return ciphertext, nil
}

func cbcDecrypt(block cipher.Block, key, iv, ciphertext []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7.Unpad(plaintext)
}

type cipherWithGCM struct {
	cipherWithBlock
}

func (c cipherWithGCM) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, iv, plaintext, nil), nil
}

func (c cipherWithGCM) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, iv, ciphertext, nil)
}
