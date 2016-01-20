package crypto

import (
	"testing"
)

func TestECSchnorrSignVerify(t *testing.T) {
	msg := []byte("Sign me")

	for _, test := range ecTestCases {
		sec := secFromTestCase(test)
		sig, err := ECSchnorrSign(msg, sec)
		if err != nil {
			t.Error(err.Error())
		}

		err = sig.Verify(msg, &sec.ECPublic)
		if err != nil {
			t.Error(err.Error())
		}
	}
}
