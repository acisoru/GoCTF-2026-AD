package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

const flagReferenceVersion = 1

type flagReference struct {
	Version int    `json:"v"`
	Vuln    int    `json:"p"`
	ID      string `json:"id"`
	GrantID string `json:"grant,omitempty"`
	Secret  string `json:"s"`
}

type privateState struct {
	Token string `json:"token"`
}

func newFlagReference(vuln int, id, grantID, token, flag string) (string, error) {
	secret, err := sealState(flag, privateState{Token: token})
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(flagReference{
		Version: flagReferenceVersion,
		Vuln:    vuln,
		ID:      id,
		GrantID: grantID,
		Secret:  secret,
	})
	if err != nil {
		return "", fmt.Errorf("marshal flag reference: %w", err)
	}
	return string(data), nil
}

func parseFlagReference(raw, flag string, vuln int) (flagReference, privateState, error) {
	var ref flagReference
	if err := json.Unmarshal([]byte(raw), &ref); err != nil {
		return ref, privateState{}, fmt.Errorf("decode flag reference: %w", err)
	}
	if ref.Version != flagReferenceVersion {
		return ref, privateState{}, fmt.Errorf("unsupported flag reference version %d", ref.Version)
	}
	if ref.Vuln != vuln {
		return ref, privateState{}, fmt.Errorf("flag reference place %d does not match requested place %d", ref.Vuln, vuln)
	}
	if ref.ID == "" || ref.Secret == "" {
		return ref, privateState{}, fmt.Errorf("incomplete flag reference")
	}
	var state privateState
	if err := openState(flag, ref.Secret, &state); err != nil {
		return ref, state, err
	}
	if state.Token == "" {
		return ref, state, fmt.Errorf("empty token in private checker state")
	}
	return ref, state, nil
}

func sealState(flag string, value any) (string, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal private checker state: %w", err)
	}
	aead, err := stateAEAD(flag)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate state nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, plain, []byte("orbit-ctf-checker-v1"))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func openState(flag, encoded string, target any) error {
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode private checker state: %w", err)
	}
	aead, err := stateAEAD(flag)
	if err != nil {
		return err
	}
	if len(sealed) < aead.NonceSize() {
		return fmt.Errorf("private checker state is truncated")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, []byte("orbit-ctf-checker-v1"))
	if err != nil {
		return fmt.Errorf("authenticate private checker state: %w", err)
	}
	if err := json.Unmarshal(plain, target); err != nil {
		return fmt.Errorf("decode private checker state payload: %w", err)
	}
	return nil
}

func stateAEAD(flag string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(flag))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create state cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create state AEAD: %w", err)
	}
	return aead, nil
}
