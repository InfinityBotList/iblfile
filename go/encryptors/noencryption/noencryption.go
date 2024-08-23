package noencryption

// No encryption source
//
// This is the simplest source type
type NoEncryptionSource struct {
}

func (p NoEncryptionSource) ID() string {
	return "noencryption$$$$"
}

// v2 specific
func (p NoEncryptionSource) Encrypt(b []byte) ([]byte, error) {
	return b, nil
}

// v2 specific
func (p NoEncryptionSource) Decrypt(b []byte) ([]byte, error) {
	return b, nil
}
