package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const tokenPrefix = "mnm"

type TokenParts struct {
	ID     string
	Secret []byte
}

func Generate() (plainText string, parts TokenParts, err error) {
	idBytes := make([]byte, 9)
	secret := make([]byte, 32)
	if _, err = rand.Read(idBytes); err != nil {
		return "", TokenParts{}, fmt.Errorf("generate token id: %w", err)
	}
	if _, err = rand.Read(secret); err != nil {
		return "", TokenParts{}, fmt.Errorf("generate token secret: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	encodedSecret := base64.RawURLEncoding.EncodeToString(secret)
	return strings.Join([]string{tokenPrefix, id, encodedSecret}, "."), TokenParts{ID: id, Secret: secret}, nil
}

func Parse(value string) (TokenParts, error) {
	fields := strings.Split(value, ".")
	if len(fields) != 3 || fields[0] != tokenPrefix || fields[1] == "" {
		return TokenParts{}, errors.New("invalid token format")
	}
	secret, err := base64.RawURLEncoding.DecodeString(fields[2])
	if err != nil || len(secret) != 32 {
		return TokenParts{}, errors.New("invalid token secret")
	}
	return TokenParts{ID: fields[1], Secret: secret}, nil
}

func Hash(secret, salt []byte) []byte {
	return argon2.IDKey(secret, salt, 2, 32*1024, 2, 32)
}

func NewSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

func Matches(secret, salt, expected []byte) bool {
	actual := Hash(secret, salt)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
