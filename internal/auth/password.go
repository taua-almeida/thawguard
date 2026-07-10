package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const passwordHashAlgorithm = "argon2id"

type passwordHashParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var defaultPasswordHashParams = passwordHashParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string) (string, error) {
	return hashPassword(password, defaultPasswordHashParams)
}

func hashPassword(password string, params passwordHashParams) (string, error) {
	if password == "" {
		return "", errors.New("password is required")
	}
	salt := make([]byte, params.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		passwordHashAlgorithm,
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password string, encodedHash string) (bool, error) {
	params, salt, expectedHash, err := decodePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}
	actualHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

func decodePasswordHash(encodedHash string) (passwordHashParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != passwordHashAlgorithm {
		return passwordHashParams{}, nil, nil, errors.New("unsupported password hash format")
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return passwordHashParams{}, nil, nil, errors.New("unsupported argon2 version")
	}
	params, err := decodePasswordHashParams(parts[3])
	if err != nil {
		return passwordHashParams{}, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return passwordHashParams{}, nil, nil, fmt.Errorf("decode password salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return passwordHashParams{}, nil, nil, fmt.Errorf("decode password hash: %w", err)
	}
	if len(salt) == 0 || len(hash) == 0 {
		return passwordHashParams{}, nil, nil, errors.New("password hash is incomplete")
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))
	return params, salt, hash, nil
}

func decodePasswordHashParams(encoded string) (passwordHashParams, error) {
	values := map[string]string{}
	for _, field := range strings.Split(encoded, ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return passwordHashParams{}, errors.New("invalid password hash parameters")
		}
		values[key] = value
	}
	memory, err := parseUint32(values["m"])
	if err != nil {
		return passwordHashParams{}, fmt.Errorf("invalid argon2 memory: %w", err)
	}
	iterations, err := parseUint32(values["t"])
	if err != nil {
		return passwordHashParams{}, fmt.Errorf("invalid argon2 iterations: %w", err)
	}
	parallelism, err := parseUint8(values["p"])
	if err != nil {
		return passwordHashParams{}, fmt.Errorf("invalid argon2 parallelism: %w", err)
	}
	if memory == 0 || iterations == 0 || parallelism == 0 {
		return passwordHashParams{}, errors.New("argon2 parameters must be positive")
	}
	return passwordHashParams{Memory: memory, Iterations: iterations, Parallelism: parallelism}, nil
}

func parseUint32(raw string) (uint32, error) {
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

func parseUint8(raw string) (uint8, error) {
	value, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, err
	}
	return uint8(value), nil
}
