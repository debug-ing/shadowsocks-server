package core

import (
	"errors"
	"net"
	shadow "shadowsocks-learn/shadow"
)

type Cipher interface {
	StreamConn(net.Conn) net.Conn
}

var ErrCipherNotSupported = errors.New("cipher not supported")

var aeadList = map[string]struct {
	KeySize int
	New     func([]byte) (shadow.Cipher, error)
}{
	aeadAes128Gcm:        {16, shadow.AESGCM},
	aeadAes256Gcm:        {32, shadow.AESGCM},
	aeadChacha20Poly1305: {32, shadow.Chacha20Poly1305},
}

const (
	aeadAes128Gcm        = "AEAD_AES_128_GCM"
	aeadAes256Gcm        = "AEAD_AES_256_GCM"
	aeadChacha20Poly1305 = "AEAD_CHACHA20_POLY1305"
)

// mod: AEAD_AES_128_GCM or AEAD_AES_256_GCM or AEAD_CHACHA20_POLY1305
func PickCipher(name string, key []byte, password string) (Cipher, error) {
	if choice, ok := aeadList[name]; ok {
		if len(key) == 0 {
			key = kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadow.KeySizeError(choice.KeySize)
		}
		aead, err := choice.New(key)
		return &aeadCipher{aead}, err
	}

	return nil, ErrCipherNotSupported
}

type aeadCipher struct{ shadow.Cipher }

func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn { return shadow.NewConn(c, aead) }
