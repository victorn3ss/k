package libkplusgenerator

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"math/rand"
)

func randomAuthenId3() string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(uuid.NewString())))
}

func randomMac() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	buf[0] |= 2

	return hex.EncodeToString(buf)
}