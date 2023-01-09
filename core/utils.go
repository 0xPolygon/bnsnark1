package core

import (
	"crypto/sha256"
	"errors"
)

// CreateRandomBlsKeys creates an slice of random private keys
func CreateRandomBlsKeys(total int) ([]*PrivateKey, error) {
	blsKeys := make([]*PrivateKey, total)

	for i := 0; i < total; i++ {
		blsKey, err := GenerateBlsKey()
		if err != nil {
			return nil, err
		}

		blsKeys[i] = blsKey
	}

	return blsKeys, nil
}

// MarshalMessage marshalls message into byte slice
func MarshalMessage(message []byte) ([]byte, error) {
	g1, err := HashToG1(message)
	if err != nil {
		return nil, err
	}

	return G1ToBytes(g1), nil
}

// HashToG103 converts message to G1 point https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-03
func HashToG103(message []byte) (*G1, error) {
	g1 := new(G1)
	if err := g1.HashAndMapTo(message); err != nil {
		return nil, err
	}

	return g1, nil
}

// HashToG107 converts message to G1 point https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-07
func HashToG107(message []byte) (*G1, error) {
	hashRes, err := hashToFpXMDSHA256(message, GetDomain(), 2)
	if err != nil {
		return nil, err
	}

	p0, p1 := new(G1), new(G1)
	u0, u1 := hashRes[0], hashRes[1]

	if err := MapToG1(p0, u0); err != nil {
		return nil, err
	}

	if err := MapToG1(p1, u1); err != nil {
		return nil, err
	}

	G1Add(p0, p0, p1)
	G1Normalize(p0, p0)

	return p0, nil
}

func hashToFpXMDSHA256(msg []byte, domain []byte, count int) ([]*Fp, error) {
	randBytes, err := expandMsgSHA256XMD(msg, domain, count*48)
	if err != nil {
		return nil, err
	}

	els := make([]*Fp, count)

	for i := 0; i < count; i++ {
		els[i], err = from48Bytes(randBytes[i*48 : (i+1)*48])
		if err != nil {
			return nil, err
		}
	}

	return els, nil
}

func expandMsgSHA256XMD(msg []byte, domain []byte, outLen int) ([]byte, error) {
	h := sha256.New()

	if len(domain) > 255 {
		return nil, errors.New("invalid domain length")
	}

	domainLen := uint8(len(domain))
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b1 := h.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.Size() - 1) / h.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			tmp[j] = b0[j] ^ bi[j]
		}
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(domain)
		_, _ = h.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
		bi = h.Sum(nil)
	}

	// b_ell
	copy(out[(ell-1)*h.Size():], bi[:])

	return out[:outLen], nil
}

func fpFromBytes(in []byte) (*Fp, error) {
	const size = 32

	if len(in) != size {
		return nil, errors.New("input string should be equal 32 bytes")
	}

	l := len(in)
	if l >= size {
		l = size
	}

	padded := make([]byte, size)

	copy(padded[size-l:], in[:])

	component := [4]uint64{}

	for i := 0; i < 4; i++ {
		a := size - i*8
		component[i] = uint64(padded[a-1]) | uint64(padded[a-2])<<8 |
			uint64(padded[a-3])<<16 | uint64(padded[a-4])<<24 |
			uint64(padded[a-5])<<32 | uint64(padded[a-6])<<40 |
			uint64(padded[a-7])<<48 | uint64(padded[a-8])<<56
	}

	fe := newFp(component[0], component[1], component[2], component[3])

	FpMul(&fe, &fe, &r2)

	return &fe, nil
}

func from48Bytes(in []byte) (*Fp, error) {
	if len(in) != 48 {
		return nil, errors.New("input string should be equal 48 bytes")
	}

	a0 := make([]byte, 32)
	copy(a0[8:32], in[:24])
	a1 := make([]byte, 32)
	copy(a1[8:32], in[24:])

	e0, err := fpFromBytes(a0)
	if err != nil {
		return nil, err
	}

	e1, err := fpFromBytes(a1)
	if err != nil {
		return nil, err
	}

	// F = 2 ^ 192 * R
	F := newFp(0xd9e291c2cdd22cd6,
		0xc722ccf2a40f0271,
		0xa49e35d611a2ac87,
		0x2e1043978c993ec8)

	FpMul(e0, e0, &F)
	FpAdd(e1, e1, e0)

	return e1, nil
}
