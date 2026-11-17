// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"errors"
	"io"
	"os"
)

var (
	errInitialBuiltInAdminState      = errors.New("initial built-in admin password: organization preflight failed")
	errInitialBuiltInAdminRead       = errors.New("initial built-in admin password file: cannot read")
	errInitialBuiltInAdminLength     = errors.New("initial built-in admin password file: invalid length")
	errInitialBuiltInAdminCharacters = errors.New("initial built-in admin password file: invalid characters")
	errInitialBuiltInAdminCreation   = errors.New("initial built-in admin creation failed")
)

// The seed callback contains the unchanged native organization/user/profile/
// consent/certificate initialization. No callback may run until preflight passes.
func withInitialBuiltInAdminPassword(path string, findOrganization func(string, string) (*Organization, error), readPassword func(string) (string, error), seed func(string)) error {
	password := ""
	if path != "" {
		organization, err := findOrganization("admin", "built-in")
		if err != nil {
			return errInitialBuiltInAdminState
		}
		// Existing installations do not read, validate, or rotate from this file.
		if organization == nil {
			password, err = readPassword(path)
			if err != nil {
				if errors.Is(err, errInitialBuiltInAdminLength) {
					return errInitialBuiltInAdminLength
				}
				if errors.Is(err, errInitialBuiltInAdminCharacters) {
					return errInitialBuiltInAdminCharacters
				}
				return errInitialBuiltInAdminRead
			}
		}
	}
	seed(password)
	return nil
}

func readInitialBuiltInAdminPassword(path string) (string, error) {
	// os.Open follows normal Kubernetes Secret-volume symlinks.
	file, err := os.Open(path)
	if err != nil {
		return "", errInitialBuiltInAdminRead
	}
	defer file.Close()
	// 72 password bytes + optional CRLF + one byte to detect oversized input.
	data, err := io.ReadAll(io.LimitReader(file, 75))
	if err != nil {
		return "", errInitialBuiltInAdminRead
	}
	if len(data) > 74 {
		return "", errInitialBuiltInAdminLength
	}
	return normalizeInitialBuiltInAdminPassword(data)
}

func normalizeInitialBuiltInAdminPassword(data []byte) (string, error) {
	// Strip exactly one final LF and its immediately preceding CR, if any.
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	if len(data) < 32 || len(data) > 72 {
		return "", errInitialBuiltInAdminLength
	}
	for _, value := range data {
		if value < 0x21 || value > 0x7e {
			return "", errInitialBuiltInAdminCharacters
		}
	}
	return string(data), nil
}
