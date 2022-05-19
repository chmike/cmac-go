package cmac

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// using test vectors from RFC4493
func TestCMAC(t *testing.T) {
	key := "2b7e151628aed2a6abf7158809cf4f3c"
	k1 := "fbeed618357133667c85e08f7236a8de"
	k2 := "f7ddac306ae266ccf90bc11ee46d513b"

	keyBytes, _ := hex.DecodeString(key)
	k1Bytes, _ := hex.DecodeString(k1)
	k2Bytes, _ := hex.DecodeString(k2)

	_, err := New(aes.NewCipher, nil)
	if err == nil {
		t.Fatal("unexpeced nil error")
	}

	cm, err := New(aes.NewCipher, keyBytes)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	tmp := cm.(*cmac)
	if !bytes.Equal(tmp.k1, k1Bytes) {
		t.Errorf("k1 mismatch, got \n   %+v\nexpected\n   %+v", tmp.k1, k1)
	}
	if !bytes.Equal(tmp.k2, k2Bytes) {
		t.Errorf("k2 mismatch, got \n   %+v\nexpected\n   %+v", tmp.k2, k2)
	}

	if !Equal(keyBytes, keyBytes) {
		t.Errorf("got equal false, expected true")
	}
	if Equal(keyBytes, k1Bytes) {
		t.Errorf("got equal true, expected false")
	}
	if Equal(keyBytes, k1Bytes[:5]) {
		t.Errorf("got equal true, expected false")
	}

	if cm.Size() != len(keyBytes) {
		t.Fatalf("expected Size %d, got %d", len(keyBytes), cm.Size())
	}

	if cm.Size() != cm.BlockSize() {
		t.Fatalf("expected same Size and BlockSize")
	}

	tests := []struct {
		msg, mac string
	}{
		{
			msg: "",
			mac: "bb1d6929e95937287fa37d129b756746",
		},
		{
			msg: "6bc1bee22e409f96e93d7e117393172a",
			mac: "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			mac: "dfa66747de9ae63030ca32611497c827",
		},
		{
			msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			mac: "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}
	for i, test := range tests {
		cm.Reset()
		msgBytes, _ := hex.DecodeString(test.msg)
		n, err := cm.Write(msgBytes)
		if err != nil {
			t.Errorf("%2d: unexpected error: %s", i, err)
			continue
		}
		if len(msgBytes) != n {
			t.Errorf("%2d: expect len %d, got %d", i, len(msgBytes), n)
			continue
		}
		macBytes, _ := hex.DecodeString(test.mac)
		if !Equal(cm.Sum(nil), macBytes) {
			t.Errorf("%2d: mac mismatch", i)
		}
	}
}

// Other test vectors
// See https://github.com/ircmaxell/PHP-PasswordLib/blob/master/test/Data/Vectors/cmac-aes.sp-800-38b.test-vectors
func TestAESCMAC2(t *testing.T) {
	tests := []struct {
		key, plain, mac string
	}{
		// 0
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
		// 5
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
		// 10
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

func TestMultiWrite(t *testing.T) {
	key := "2b7e151628aed2a6abf7158809cf4f3c"
	keyBytes, _ := hex.DecodeString(key)

	msg := "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
	msgBytes, _ := hex.DecodeString(msg)

	mac := "51f0bebf7e3b9d92fc49741779363cfe"

	cm, err := New(aes.NewCipher, keyBytes)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}

	b := msgBytes
	for len(b) > 7 {
		cm.Write(b[:7])
		b = b[7:]
		cm.Sum(nil)
	}
	cm.Write(b)

	macBytes := cm.Sum(nil)
	if hex.EncodeToString(macBytes) != mac {
		t.Fatalf("mac mismatch")
	}
}
