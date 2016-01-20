package crypto

import (
	"crypto/subtle"
	"errors"
	"math/big"
)

const (
	ECSchnorrEntropySize = 32
)

type (
	ECSchnorrCoeff [ECSchnorrEntropySize]byte

	ECSchnorrSig struct {
		E Hash
		S ECSchnorrCoeff
	}
)

var (
	ErrECSchnorrVerify = errors.New("ECSchnorr signature did not verify")
)

func ECSchnorrSign(data []byte, secKey *ECSecret) (*ECSchnorrSig, error) {
	sig := &ECSchnorrSig{}

	// Compute new public key
	k, err := RandBytes(ECSchnorrEntropySize)
	if err != nil {
		return nil, err
	}

	kPub := ComputeECPublic(k)
	serKPub := kPub.Serialize()

	// Concatenate data and serialized kPub
	hashData := make([]byte, len(data)+len(serKPub))
	copy(hashData[:len(data)], data)
	copy(hashData[len(data):], serKPub)

	// Compute non-interactive challenge
	sig.E = HashBytes(hashData)

	kInt := new(big.Int).SetBytes(k)
	eInt := new(big.Int).SetBytes(sig.E[:])

	// Compute s = k - er
	s := new(big.Int)
	s.Mul(eInt, secKey.R)
	s.Sub(kInt, s)
	s.Mod(s, s256.N)

	// Copy s value into Hash array
	sBytes := s.Bytes()
	offset := HashSize - len(sBytes)
	copy(sig.S[offset:], sBytes)

	return sig, nil
}

func (sig *ECSchnorrSig) Verify(data []byte, pubKey *ECPublic) error {
	// Compute kG = sG + erG
	sGx, sGy := s256.ScalarBaseMult(sig.S[:])
	ePubx, ePuby := s256.ScalarMult(pubKey.X, pubKey.Y, sig.E[:])
	kGx, kGy := s256.Add(sGx, sGy, ePubx, ePuby)

	// Serialize point
	kG := &ECPublic{kGx, kGy}
	serPub := kG.Serialize()

	// Concatenate data and serialized kPub
	hashData := make([]byte, len(data)+len(serPub))
	copy(hashData[:len(data)], data)
	copy(hashData[len(data):], serPub)

	e := HashBytes(hashData)

	// Use constant time byte comparison to avoid timing attacks
	if subtle.ConstantTimeCompare(e[:], sig.E[:]) != 1 {
		return ErrECSchnorrVerify
	}

	return nil
}
