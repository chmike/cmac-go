
#Cipher-based Message Authentication Code

This package implements the Cipher-based Message Authentication Code as
defined in the RFC4493 and NIST special publication 800-38B, "Recommendation
for Block Cipher Modes of Operation: The CMAC Mode for Authentication", May 2005.

It achieves a security goal similar to that of HMAC, but uses a symmetric key
block cipher like AES. CMAC is appropriate for information systems in which a
block cipher is more readily available than a hash function.

Like HMAC, CMAC uses a key to sign a message. The receiver verifies the
Massage Authenticating Code by recomputing it using the same key.

## Instalation

    go get -u github.com/chmike/cmac-go

## Usage example

    import (
        "crypto/aes"

        "github.com/chmike/cmac-go"
    )

    // Instantiate the cmac hash.Hash.
    cm, err := cmac.New(aes.NewCipher, key)
    if err != nil {
        // ...
    }

    // Compute the CMAC of a message. Never returns an error.
    // The parameter may be an empty slice or nil.
    cm.Write([]byte("some message"))

    // Get the computed MAC.
    mac1 := cm.Sum(nil)

    // Important: use cmac.Equal() instead of bytes.Equal().
    // It doesn't leak timing information.
    if !cmac.Equal(mac1, mac2) {
        // mac mismatch
    }
