package main

/*
#include <stdint.h>
*/
import "C"
import (
	"crypto/ecdsa"
	"kplus/shared"
	_ "reflect"
	"runtime/cgo"
)

func main() {
}

type sessionHandle struct {
	id         string
	privateKey *ecdsa.PrivateKey
	key        []byte
	iv         []byte
}

func (c *sessionHandle) encrypt(data string) (string, error) {
	dst, err := shared.AesCBCEncrypt([]byte(data), c.key, c.iv)
	if err != nil {
		return "", err
	}

	return shared.Base64Encode(dst), nil
}

func (c *sessionHandle) decrypt(src string) (string, error) {
	b, err := shared.Base64Decode(src)
	if err != nil {
		return "", err
	}

	dst, err := shared.AesCBCDecrypt(b, c.key, c.iv)
	if err != nil {
		return "", err
	}

	return string(dst), nil
}

//export NewSession
func NewSession() C.uintptr_t {
	privateKey, err := shared.GenerateKey()
	if err != nil {
		return 0
	}

	return C.uintptr_t(cgo.NewHandle(&sessionHandle{
		id:         shared.GenerateSessionId(),
		privateKey: privateKey,
	}))
}

//export GetSessionId
func GetSessionId(handle C.uintptr_t) *C.char {
	session := sessionFromHandle(handle)
	if session == nil {
		return nil
	}

	return C.CString(session.id)
}

//export GetPublicKey
func GetPublicKey(handle C.uintptr_t) *C.char {
	session := sessionFromHandle(handle)
	if session == nil {
		return nil
	}

	return C.CString(shared.MarshalPublicKey(&session.privateKey.PublicKey))
}

//export Exchange
func Exchange(handle C.uintptr_t, key *C.char) C.uint8_t {
	session := sessionFromHandle(handle)
	if session == nil {
		return 0
	}

	publicKey, err := shared.ParsePublicKey(C.GoString(key))
	if err != nil {
		return 0
	}

	sharedKey, _ := session.privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, session.privateKey.D.Bytes())

	session.key = sharedKey.Bytes()
	session.iv = []byte(session.id[6:22])

	return 1
}

//export Encrypt
func Encrypt(handle C.uintptr_t, data *C.char) *C.char {
	session := sessionFromHandle(handle)
	if session == nil {
		return nil
	}
	if len(session.key) == 0 {
		return nil
	}

	encrypted, err := session.encrypt(C.GoString(data))
	if err != nil {
		return nil
	}

	return C.CString(encrypted)
}

//export Decrypt
func Decrypt(handle C.uintptr_t, data *C.char) *C.char {
	session := sessionFromHandle(handle)
	if session == nil {
		return nil
	}
	if len(session.key) == 0 {
		return nil
	}

	decrypted, err := session.decrypt(C.GoString(data))
	if err != nil {
		return nil
	}

	return C.CString(decrypted)
}

//export Close
func Close(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

func sessionFromHandle(handle C.uintptr_t) *sessionHandle {
	v, ok := cgo.Handle(handle).Value().(*sessionHandle)
	if !ok {
		return nil
	}

	return v
}
