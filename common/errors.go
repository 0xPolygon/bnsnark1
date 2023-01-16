package common

import "errors"

var (
	ErrEmptyKeyMarshalling = errors.New("cannot marshal empty private key")
	ErrPrivateKeyGenerator = errors.New("error generating private key")
)
