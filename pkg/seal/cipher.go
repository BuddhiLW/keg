// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

// Cipher is the port every encryption backend implements.
type Cipher interface {
	// Encrypt returns plain as one ASCII-armored message readable by
	// every recipient. Empty recipients means the backend's default
	// (for gpg, the user's own key).
	Encrypt(plain []byte, to Recipients) (armor string, err error)

	// Decrypt returns the plaintext of armor, using whichever secret key
	// the backend holds.
	Decrypt(armor string) ([]byte, error)
}
