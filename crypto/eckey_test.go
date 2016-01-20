package crypto

import (
	"bytes"
	"math/big"
	"testing"
)

type ecTestCase struct {
	R string
	X string
	Y string
}

var ecTestCases = []ecTestCase{
	ecTestCase{
		R: "1",
		X: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		Y: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
	},
	ecTestCase{
		R: "2",
		X: "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		Y: "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
	},
	ecTestCase{
		R: "3",
		X: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		Y: "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
	},
	ecTestCase{
		R: "17",
		X: "DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
		Y: "4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77",
	},
	ecTestCase{
		R: "115792089237316195423570985008687907852837564279074904382605163141518161494329",
		X: "2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01",
		Y: "A3B25758BEAC66B6D6C2F7D5ECD2EC4B3D1DEC2945A489E84A25D3479342132B",
	},
	ecTestCase{
		R: "115792089237316195423570985008687907852837564279074904382605163141518161494336",
		X: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		Y: "B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777",
	},
}

/*
 * Test case serialization
 */

func pubFromTestCase(test ecTestCase) *ECPublic {
	x, _ := new(big.Int).SetString(test.X, 16)
	y, _ := new(big.Int).SetString(test.Y, 16)

	return &ECPublic{x, y}
}

func secFromTestCase(test ecTestCase) *ECSecret {
	pub := pubFromTestCase(test)
	r, _ := new(big.Int).SetString(test.R, 10)

	return &ECSecret{*pub, r}
}

/*
 * Public Key Generation Tests
 */

func TestComputeECPublic(t *testing.T) {
	for _, test := range ecTestCases {
		sec := secFromTestCase(test)

		pub := ComputeECPublic(sec.R.Bytes())

		if pub.X.Cmp(sec.X) != 0 || pub.Y.Cmp(sec.Y) != 0 {
			t.Error("Failed to create public key from scalar.")
		}
	}
}

/*
 * Serialization and Compression Tests
 */

func TestSerializationPublic(t *testing.T) {
	for _, test := range ecTestCases {
		// Construct test ECPublic key
		pub := pubFromTestCase(test)

		// Serialize and deserialize
		pubBytes := pub.Serialize()
		pub2, err := DeserializeECPublic(pubBytes)

		if err != nil {
			t.Error(err.Error())
		}

		if pub.X.Cmp(pub2.X) != 0 || pub.Y.Cmp(pub2.Y) != 0 {
			t.Error("Deserialized ECPublic does not match original")
		}
	}
}

func TestSerializationSecret(t *testing.T) {
	for _, test := range ecTestCases {
		sec := secFromTestCase(test)

		secBytes := sec.Serialize()
		sec2, err := DeserializeECSecret(secBytes)

		if err != nil {
			t.Error(err.Error())
		}

		if sec2.R.Cmp(sec.R) != 0 || sec2.X.Cmp(sec.X) != 0 || sec2.Y.Cmp(sec.Y) != 0 {
			t.Error("Deserialized ECSecret does not match original")
		}
	}
}

func TestCompressionPublic(t *testing.T) {
	for _, test := range ecTestCases {
		pub := pubFromTestCase(test)

		// Compress and uncompress
		cmpPubBytes := pub.Compress()
		pub2, err := UncompressECPublic(cmpPubBytes)

		if err != nil {
			t.Error(err.Error())
		}

		if pub.X.Cmp(pub2.X) != 0 || pub.Y.Cmp(pub2.Y) != 0 {
			t.Error("Uncompressed ECPublic does not match original")
		}
	}
}

/*
 * Padding Tests
 */

var paddingTests = []struct {
	Bytes    []byte
	Expected []byte
}{
	{
		// Nil byte slice
		Bytes: nil,
		Expected: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0},
	},
	{
		// Empty byte slice
		Bytes: []byte{},
		Expected: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0},
	},
	{
		// Small byte slice
		Bytes: []byte{0x1},
		Expected: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x1},
	},
	{
		// ECCoordinateSize byte slice
		Bytes: []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x1},
		Expected: []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x1},
	},
	{
		// Large byte slice
		Bytes: []byte{0x1, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
		Expected: []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x1},
	},
}

func TestPadECCoordinateSize(t *testing.T) {
	for _, test := range paddingTests {
		padded := pad(test.Bytes, ECCoordinateSize)
		if bytes.Compare(padded, test.Expected) != 0 {
			t.Error("Padded input does not equal expected output")
		}
	}
}
