package shared

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

var GenerateSessionId func() string
var GenerateKey func() (*ecdsa.PrivateKey, error)
var newCipher func(key []byte) (cipher.Block, error)
var newEncrypter func(b cipher.Block, iv []byte) cipher.BlockMode
var newDecrypter func(b cipher.Block, iv []byte) cipher.BlockMode
var parsePKIXPublicKey func(derBytes []byte) (pub interface{}, err error)
var marshalPKIXPublicKey func(pub interface{}) ([]byte, error)
var Base64Encode func(src []byte) string
var Base64Decode func(s string) ([]byte, error)
var hexEncode func(src []byte) string
var hexDecode func(s string) ([]byte, error)

func init() {
	GenerateSessionId = func() string {
		return strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	GenerateKey = func() (*ecdsa.PrivateKey, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	newCipher = func(key []byte) (cipher.Block, error) {
		return aes.NewCipher(key)
	}
	newEncrypter = func(b cipher.Block, iv []byte) cipher.BlockMode {
		return cipher.NewCBCEncrypter(b, iv)
	}
	newDecrypter = func(b cipher.Block, iv []byte) cipher.BlockMode {
		return cipher.NewCBCDecrypter(b, iv)
	}
	parsePKIXPublicKey = func(derBytes []byte) (pub interface{}, err error) {
		return x509.ParsePKIXPublicKey(derBytes)
	}
	marshalPKIXPublicKey = func(pub interface{}) ([]byte, error) {
		return x509.MarshalPKIXPublicKey(pub)
	}
	Base64Encode = func(src []byte) string {
		return base64.StdEncoding.EncodeToString(src)
	}
	Base64Decode = func(s string) ([]byte, error) {
		return base64.StdEncoding.DecodeString(s)
	}
	hexEncode = func(src []byte) string {
		return hex.EncodeToString(src)
	}
	hexDecode = func(s string) ([]byte, error) {
		return hex.DecodeString(s)
	}
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	c := blockSize - len(data)%blockSize

	return append(data, bytes.Repeat([]byte{byte(c)}, c)...)
}

func pkcs7UnPadding(data []byte) []byte {
	return data[:(len(data) - int(data[len(data)-1]))]
}

func AesCBCEncrypt(src, key, iv []byte) ([]byte, error) {
	block, _ := newCipher(key)

	src = pkcs7Padding(src, block.BlockSize())
	dst := make([]byte, len(src))
	mode := newEncrypter(block, iv)
	mode.CryptBlocks(dst, src)

	return dst, nil
}

func AesCBCDecrypt(src, key, iv []byte) ([]byte, error) {
	block, err := newCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()

	if len(src) < blockSize {
		return nil, errors.New("ciphertext too short")
	}

	if len(src)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	dst := make([]byte, len(src))
	mode := newDecrypter(block, iv)
	mode.CryptBlocks(dst, src)

	return pkcs7UnPadding(dst), nil
}

func MarshalPublicKey(publicKey *ecdsa.PublicKey) string {
	pkixPublicKey, err := marshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}

	return hexEncode(pkixPublicKey)
}

func ParsePublicKey(s string) (*ecdsa.PublicKey, error) {
	b, err := hexDecode(s)
	if err != nil {
		return nil, err
	}

	pkixPublicKey, err := parsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pkixPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unmarshal public key")
	}

	return publicKey, nil
}

var (
	dnsResolverIP        = "8.8.8.8:53"
	dnsResolverProto     = "udp"
	dnsResolverTimeoutMs = 5000
)

func NewHttpClient() *http.Client {
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext:     dialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		Jar: jar,
	}
}
