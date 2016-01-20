package crypto

import (
	"errors"
	"math/big"
)

const (
	// ECCoordinateSize defines the number of bytes required to store the x or y
	// coordinate of an secp256k1 point.
	ECCoordinateSize = 32

	// ECHeaderCompressedEven defines the header byte of a compressed EC point
	// indicating that the even Y coordinate should be chosen upon decompression.
	ECHeaderCompressedEven byte = 0x02

	// ECHeaderCompressedOdd defines the header byte of a compressed EC point
	// indicating that the odd Y coordinate should be chosen upon decompression.
	ECHeaderCompressedOdd byte = 0x03

	// ECHeaderUncompressed defines the header byte of an uncompressed EC point.
	ECHeaderUncompressed byte = 0x04

	// ECHeaderSerializedSecret defines the header byte of a serialized EC secret
	// key.
	ECHeaderSerializedSecret byte = 0x08
)

type (
	// ECPublic represents an (X, Y) point on secp256k1 curve
	ECPublic struct {
		X *big.Int
		Y *big.Int
	}

	// ECSecret represents an ECPublic along with the known secret key used to
	// generate the point.
	ECSecret struct {
		ECPublic
		R *big.Int
	}
)

var (
	// ErrInvalidCompressedPublic signifies that the compressed EC public key is
	// formatted improperly.
	ErrInvalidCompressedPublic = errors.New("Invalid compressed ECPublic")

	// ErrInvalidSerializedPublic signifies that the serialized EC public key is
	// formatted improperly.
	ErrInvalidSerializedPublic = errors.New("Invalid serialized ECPublic")

	// ErrInvalidSerializedSecret signifies that the serialized EC secret key is
	// formatted improperly.
	ErrInvalidSerializedSecret = errors.New("Invalid serialized ECSecret")

	// Defines the highest order exponent for secp256k1 curve equation, e.g. x^3.
	bigThree = new(big.Int).SetUint64(3)

	// Defines the exponent used to calculate the square root of an secp256k1
	// point.  This value is calculated as (P+1)/4.
	sqRootExp, _ = new(big.Int).SetString("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C", 16)
)

// ComputeECPublic takes a byte array representing a secret value r and computes
// the associated public key rG.  The length of the byte array can be no more
// than 32, otherwise ScalarBaseMult will panic.
func ComputeECPublic(rBytes []byte) *ECPublic {
	// Compute public key, rG.
	rGx, rGy := s256.ScalarBaseMult(rBytes)

	return &ECPublic{rGx, rGy}
}

// Serialize returns the byte array representing an uncompressed EC public key.
func (pub *ECPublic) Serialize() []byte {
	// Signify that data is an uncompressed EC public key.
	data := []byte{ECHeaderUncompressed}

	// Pad X and Y coordinates to ECCoordinateSize
	padx := pad(pub.X.Bytes(), ECCoordinateSize)
	pady := pad(pub.Y.Bytes(), ECCoordinateSize)

	// Append after header
	data = append(data, padx...)
	data = append(data, pady...)

	return data
}

// DeserializeECPublic reconstructs an ECPublic from a byte slice.  Throws an
// ErrInvalidSerializedPublic if the slice is nil or improperly formatted.
func DeserializeECPublic(data []byte) (*ECPublic, error) {
	// Verify data existence and length
	if data == nil || len(data) != 1+2*ECCoordinateSize {
		return nil, ErrInvalidSerializedPublic
	}

	// Verify correctness of header
	if data[0] != ECHeaderUncompressed {
		return nil, ErrInvalidSerializedPublic
	}

	// Parse X and Y bytes from data
	xBytes := data[1 : 1+ECCoordinateSize]
	yBytes := data[1+ECCoordinateSize:]

	// Assemble ECPublic key
	pub := &ECPublic{
		X: new(big.Int).SetBytes(xBytes),
		Y: new(big.Int).SetBytes(yBytes),
	}

	return pub, nil
}

// Serialize returns the byte array representing an uncompressed EC secret key.
func (sec *ECSecret) Serialize() []byte {
	// Signify that data is a serialized EC secret key
	data := []byte{ECHeaderSerializedSecret}

	// Pad R value to ECCoordinateSize
	padr := pad(sec.R.Bytes(), ECCoordinateSize)

	// Append after header
	data = append(data, padr...)

	return data
}

func DeserializeECSecret(data []byte) (*ECSecret, error) {
	// Verify data existence and length
	if len(data) != 1+ECCoordinateSize {
		return nil, ErrInvalidSerializedSecret
	}

	// Verify header correctness
	if data[0] != ECHeaderSerializedSecret {
		return nil, ErrInvalidSerializedSecret
	}

	// Parse secret bytes and compute public key
	rBytes := data[1:]
	pubKey := ComputeECPublic(rBytes)

	// Assemble secret key
	secKey := &ECSecret{
		ECPublic: *pubKey,
		R:        new(big.Int).SetBytes(rBytes),
	}

	return secKey, nil
}

func (pub *ECPublic) Compress() []byte {
	// Get last byte of Y component and compute parity.
	parity := bigIntParity(pub.Y)

	// Set header based on parity of Y component
	var header byte
	if parity == 0 {
		header = ECHeaderCompressedEven
	} else {
		header = ECHeaderCompressedOdd
	}

	// Encode header and append padded X coordinate
	data := []byte{header}
	padx := pad(pub.X.Bytes(), ECCoordinateSize)
	data = append(data, padx...)

	return data
}

func UncompressECPublic(data []byte) (*ECPublic, error) {
	// Verify data existence and length
	if data == nil || len(data) != 1+ECCoordinateSize {
		return nil, ErrInvalidCompressedPublic
	}

	// Verify header value
	header := data[0]
	if header != ECHeaderCompressedEven && header != ECHeaderCompressedOdd {
		return nil, ErrInvalidCompressedPublic
	}

	xBytes := data[1:]
	x := new(big.Int).SetBytes(xBytes)

	// x^3 + b mod P
	yTemp := new(big.Int)
	yTemp.Exp(x, bigThree, s256.P)
	yTemp.Add(yTemp, s256.B)
	yTemp.Mod(yTemp, s256.P)

	// Compute square root, yTemp^(p+1)/4 mod P
	yTemp.Exp(yTemp, sqRootExp, s256.P)

	// Select Y component based on header and yTemp parity
	yParity := bigIntParity(yTemp)
	headerParity := header % 2

	// If yParity and headerParity differ, use other Y coordinate
	if yParity^headerParity != 0 {
		yTemp.Sub(s256.P, yTemp)
		yTemp.Mod(yTemp, s256.P)
	}

	return &ECPublic{x, yTemp}, nil
}

// bigIntParity returns a byte indicating the parity of the given big.Int
func bigIntParity(i *big.Int) byte {
	iBytes := i.Bytes()
	lastByteI := iBytes[len(iBytes)-1]

	return lastByteI % 2
}

// padECCoordinateSize pads a given byte array to have length ECCoordinateSize.
// If the byte array is longer than ECCoordinateSize, the last ECCoordinateSize
// bytes are returned.
func pad(bytes []byte, size int) []byte {
	if bytes == nil {
		return make([]byte, size)
	}

	// If byte array is already ECCoordinateSize, simply return
	if len(bytes) >= size {
		offset := len(bytes) - size
		return bytes[offset:]
	}

	// Otherwise, create new array and copy big-endian bytes after offset
	padded := make([]byte, size)
	offset := size - len(bytes)
	copy(padded[offset:], bytes)

	return padded
}
