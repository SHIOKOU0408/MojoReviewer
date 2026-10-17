package feishu

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

func decryptEvent(encryptKey, encrypted string) ([]byte, error) {
	if strings.TrimSpace(encryptKey) == "" {
		return nil, fmt.Errorf("encrypt_key 为空")
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encrypted))
	if err != nil {
		return nil, fmt.Errorf("密文无法解码")
	}
	if len(data) < aes.BlockSize*2 || (len(data)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度无效")
	}
	key := sha256.Sum256([]byte(encryptKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(data)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, data[:aes.BlockSize]).CryptBlocks(plain, data[aes.BlockSize:])
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plain) {
		return nil, fmt.Errorf("填充无效")
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, fmt.Errorf("填充无效")
		}
	}
	return plain[:len(plain)-padding], nil
}
