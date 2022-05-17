package cmac

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func TestCMAC(t *testing.T) {
	var key = []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	var k1 = []byte{0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66, 0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde}
	var k2 = []byte{0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc, 0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b}

	cm, err := New(aes.NewCipher, key)
	if err != nil {
		panic(err)
	}
	tmp := cm.(*cmac)
	if !bytes.Equal(tmp.k1, k1) {
		t.Errorf("k1 mismatch, got \n   %+v\nexpected\n   %+v", tmp.k1, k1)
	}
	if !bytes.Equal(tmp.k2, k2) {
		t.Errorf("k2 mismatch, got \n   %+v\nexpected\n   %+v", tmp.k2, k2)
	}

	if !Equal(key, key) {
		t.Errorf("got equal false, expected true")
	}
	if Equal(key, k1) {
		t.Errorf("got equal true, expected false")
	}
	if Equal(key, k1[:5]) {
		t.Errorf("got equal true, expected false")
	}

	tests := []struct {
		msg, mac []byte
	}{
		{
			msg: nil,
			mac: []byte{0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46},
		},
		{
			msg: []byte{},
			mac: []byte{0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46},
		},
		{
			msg: []byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
			mac: []byte{0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c},
		},
		{
			msg: []byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11},
			mac: []byte{0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27},
		},
		{
			msg: []byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
				0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
				0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
				0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10},
			mac: []byte{0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe},
		},
	}
	for i, test := range tests {
		cm.Reset()
		n, err := cm.Write(test.msg)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
			continue
		}
		if len(test.msg) != n {
			t.Errorf("got len %d, expected %d for test %d", n, len(test.msg), i)
			continue
		}
		if !Equal(cm.Sum(nil), test.mac) {
			t.Errorf("mac mismatch for test %d", i)
		}
	}
}

// Other test vectors
// See https://github.com/ircmaxell/PHP-PasswordLib/blob/master/test/Data/Vectors/cmac-aes.sp-800-38b.test-vectors
func TestAESCMAC2(t *testing.T) {
	tests := []struct {
		key, plain, mac string
	}{
		{
			key:   "2b7e151628aed2a6abf7158809cf4f3c",
			plain: "",
			mac:   "bb1d6929e95937287fa37d129b756746",
		},
		{
			key:   "2b7e151628aed2a6abf7158809cf4f3c",
			plain: "6bc1bee22e409f96e93d7e117393172a",
			mac:   "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			key:   "2b7e151628aed2a6abf7158809cf4f3c",
			plain: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			mac:   "dfa66747de9ae63030ca32611497c827",
		},
		{
			key:   "2b7e151628aed2a6abf7158809cf4f3c",
			plain: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			mac:   "51f0bebf7e3b9d92fc49741779363cfe",
		},
		{
			key:   "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
			plain: "",
			mac:   "d17ddf46adaacde531cac483de7a9367",
		},
		{
			key:   "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
			plain: "6bc1bee22e409f96e93d7e117393172a",
			mac:   "9e99a7bf31e710900662f65e617c5184",
		},
		{
			key:   "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
			plain: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			mac:   "8a1de5be2eb31aad089a82e6ee908b0e",
		},
		{
			key:   "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
			plain: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			mac:   "a1d5df0eed790f794d77589659f39a11",
		},
		{
			key:   "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
			plain: "",
			mac:   "028962f61b7bf89efc6b551f4667d983",
		},
		{
			key:   "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
			plain: "6bc1bee22e409f96e93d7e117393172a",
			mac:   "28a7023f452e8f82bd4bf28d8c37c35c",
		},
		{
			key:   "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
			plain: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			mac:   "aaf3d8f1de5640c232f5b169b9c911e6",
		},
		{
			key:   "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
			plain: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			mac:   "e1992190549f6ed5696a2c056c315410",
		},
	}

	for i, test := range tests {
		refKey, _ := hex.DecodeString(test.key)
		plain, _ := hex.DecodeString(test.plain)
		refMac, _ := hex.DecodeString(test.mac)
		cm, err := New(aes.NewCipher, refKey)
		if err != nil {
			panic(err)
		}
		cm.Reset()
		n, err := cm.Write(plain)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
			continue
		}
		if len(plain) != n {
			t.Errorf("got len %d, expected %d for test %d", n, len(plain), i)
			continue
		}
		if !Equal(cm.Sum(nil), refMac) {
			t.Errorf("mac mismatch for test %d", i)
		}
	}
}
