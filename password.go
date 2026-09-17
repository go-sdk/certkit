package certkit

import (
	"bytes"
	"strings"

	"github.com/go-sdk/core/errx"
)

func passwordFor(options OpenOptions, request PasswordRequest) ([]byte, error) {
	if options.Password != nil {
		return options.Password, nil
	}
	if options.PasswordProvider != nil {
		password, err := options.PasswordProvider(request)
		if err != nil {
			return nil, errx.Wrap(err, "get password")
		}
		if password != nil {
			return password, nil
		}
	}
	return nil, ErrPassword
}

func appendUniquePassword(passwords [][]byte, password []byte) [][]byte {
	if password == nil {
		return passwords
	}
	for _, current := range passwords {
		if bytes.Equal(current, password) {
			return passwords
		}
	}
	return append(passwords, password)
}

func passwordByAlias(passwords map[string][]byte, alias string) ([]byte, bool) {
	if password, ok := passwords[alias]; ok {
		return password, true
	}
	for candidate, password := range passwords {
		if strings.EqualFold(candidate, alias) {
			return password, true
		}
	}
	return nil, false
}
