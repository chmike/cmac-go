/*
Package cmac implements the Cipher-based Message Authentication Code as
defined in the RFC4493 and NIST special publication 800-38B, "Recommendation
for Block Cipher Modes of Operation: The CMAC Mode for Authentication", May 2005.

It achieves a security goal similar to that of HMAC, but uses a symmetric key
block cipher like AES. CMAC is appropriate for information systems in which a
block cipher is more readily available than a hash function.

Like HMAC, CMAC uses a key to sign a message. The receiver verifies the
Massage Authenticating Code by recomputing it using the same key.

Receivers should be careful to use Equal to compare MACs in order to avoid
timing side-channels:

	// CheckMAC reports whether messageMAC is a valid HMAC tag for message.
	func CheckMAC(message, messageMAC, key []byte) bool {
		mac := cmac.New(aes.New, key)
		mac.Write(message)
		expectedMAC := mac.Sum(nil)
		return cmac.Equal(messageMAC, expectedMAC)
	}
*/
package cmac

import (
	"crypto/cipher"
	"hash"
)

/* CMAC uses mac with no iv to compute the MAC.

    +-----+     +-----+     +-----+     +-----+     +-----+     +---+----+
    | M_1 |     | M_2 |     | M_n |     | M_1 |     | M_2 |     |M_n|10^i|
    +-----+     +-----+     +-----+     +-----+     +-----+     +---+----+
       |           |           |   +--+    |           |           |   +--+
       |     +--->(+)    +--->(+)<-|K1|    |     +--->(+)    +--->(+)<-|K2|
       |     |     |     |     |   +--+    |     |     |     |     |   +--+
    +-----+  |  +-----+  |  +-----+     +-----+  |  +-----+  |  +-----+
    |AES_K|  |  |AES_K|  |  |AES_K|     |AES_K|  |  |AES_K|  |  |AES_K|
    +-----+  |  +-----+  |  +-----+     +-----+  |  +-----+  |  +-----+
       |     |     |     |     |           |     |     |     |     |
       +-----+     +-----+     |           +-----+     +-----+     |
                               |                                   |
                            +-----+                              +-----+
                            |  T  |                              |  T  |
                            +-----+                              +-----+

	Illustration of the two cases of CMAC computation using the cipher AES.

The case on the left is when the number of bytes of the message is a multiple
of the block size. The case of the right is when padding bits must be
appended to the last block to get a full block. The padding is the bit 1
followed by as many bit 0 as required.

K1 and K2 have the size of a block and are computed as follow:

   const_zero = [0, ..., 0, 0]
   const_Rb   = [0, ..., 0, 0x87]

   Step 1.  L := AES-128(K, const_Zero);
   Step 2.  if MostSignificantBit(L) is equal to 0
            then    K1 := L << 1;
            else    K1 := (L << 1) XOR const_Rb;
   Step 3.  if MostSignificantBit(K1) is equal to 0
            then    K2 := K1 << 1;
            else    K2 := (K1 << 1) XOR const_Rb;
*/

type cmac struct {
	blockSize   int
	mac, k1, k2 []byte
	cipher      cipher.Block
}

// NewCipherFunc instatiates a block cipher
type NewCipherFunc func(key []byte) (cipher.Block, error)

// New returns a new CMAC hash using the given cipher instatiation function and key.
func New(newCipher NewCipherFunc, key []byte) (hash.Hash, error) {
	c, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	var bs = c.BlockSize()
	var cm = new(cmac)
	cm.blockSize = bs
	cm.mac = make([]byte, 3*bs)
	cm.k1, cm.k2 = cm.mac[bs:2*bs], cm.mac[2*bs:]
	cm.mac = cm.mac[:bs]
	cm.cipher = c
	c.Encrypt(cm.k1, cm.k1)
	tmp := cm.k1[0]
	shiftLeftOneBit(cm.k1, cm.k1)
	cm.k1[bs-1] ^= 0x87 & byte(int8(tmp)>>7) // xor with 0x87 when most significant bit of tmp is 1
	tmp = cm.k1[0]
	shiftLeftOneBit(cm.k2, cm.k1)
	cm.k2[bs-1] ^= 0x87 & byte(int8(tmp)>>7) // xor with 0x87 when most significant bit of tmp is 1
	return cm, nil
}

func (c *cmac) Size() int { return c.blockSize }

func (c *cmac) BlockSize() int { return c.blockSize }

func shiftLeftOneBit(dst, src []byte) {
	var overflow byte
	for i := len(src) - 1; i >= 0; i-- {
		var tmp = src[i]
		dst[i] = (tmp << 1) | overflow
		overflow = tmp >> 7
	}
}

func (c *cmac) Write(m []byte) (n int, err error) {
	n = len(m)
	for len(m) > c.blockSize {
		for i := range c.mac {
			c.mac[i] ^= m[i]
		}
		c.cipher.Encrypt(c.mac, c.mac)
		m = m[c.blockSize:]
	}
	if len(m) == c.blockSize {
		for i := range c.mac {
			c.mac[i] ^= c.k1[i] ^ m[i]
		}
	} else {
		for i := range c.mac {
			c.mac[i] ^= c.k2[i]
		}
		for i := range m {
			c.mac[i] ^= m[i]
		}
		c.mac[len(m)] ^= 0x80
	}
	c.cipher.Encrypt(c.mac, c.mac)
	return
}

func (c *cmac) Sum(in []byte) []byte {
	return append(in, c.mac...)
}

// Reset the the CMAC
func (c *cmac) Reset() {
	for i := range c.mac {
		c.mac[i] = 0
	}
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(mac1, mac2 []byte) bool {
	if len(mac1) != len(mac2) {
		return false
	}
	// copied from libsodium
	var b byte
	for i := range mac1 {
		b |= mac1[i] ^ mac2[i]
	}
	return ((uint16(b)-1)>>8)&1 == 1
}
