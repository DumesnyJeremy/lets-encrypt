package lets_encrypt

import (
	"testing"
)

// Only test the 2 converters, all the other methods are not possible to test because of the
// the non-presence of an Interface with all the Let's Encrypt Methods. The construction of the
// lib, with structure into struct does not allow us to mock the methods.

const privKey = "-----BEGIN PRIVATE KEY-----\n" +
	"MIGkAgEBBDA0cujlLGX7mxHpPdp79oyxaEcBDNGh73h5Sf0EH/O5RYN8QRnjAbIt\n" +
	"trMTa5aPPs6gBwYFK4EEACKhZANiAASeC42yxl4qmRRWpxNhEn2BD2ZWRF5Ee/BU\n" +
	"1JtWM5CA3EzYIM43TGiyB+6kFBFbaLu/x7a0+h0oVrrjuV52IP9dUGjQFqJzpneu\n" +
	"HExSfoej2NqaN9rbTk+cZUaPcS5A298=\n" +
	"-----END PRIVATE KEY-----\n"
const pubKey = "-----BEGIN PUBLIC KEY-----\n" +
	"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEnguNssZeKpkUVqcTYRJ9gQ9mVkReRHvw\n" +
	"VNSbVjOQgNxM2CDON0xosgfupBQRW2i7v8e2tPodKFa647lediD/XVBo0Baic6Z3\n" +
	"rhxMUn6Ho9jamjfa205PnGVGj3EuQNvf\n" +
	"-----END PUBLIC KEY-----\n"

func TestGoodKeyConverter(t *testing.T) {
	privEncodeKey, pubEncodeKey, err := stringToKey(privKey, pubKey)
	if err != nil {
		t.Error("Error: ", err)
	}
	privateKey, err := convertX509PrivateKeyToString(privEncodeKey)
	if err != nil {
		t.Error("Error: ", err)
	}
	publicKey, err := convertX509PublicKeyToString(pubEncodeKey)
	if err != nil {
		t.Error("Error: ", err)
	}
	if privKey != privateKey {
		t.Error("Error: didn't convert well the Private Key")
	}
	if pubKey != publicKey {
		t.Error("Error: didn't convert well the Public Key")
	}
}

func TestBadKeyConverter(t *testing.T) {
	privEncodeKey, pubEncodeKey, err := stringToKey(privKey, "")
	if err != nil {
		t.Error("Error:", err)
	}
	privateKey, err := convertX509PrivateKeyToString(privEncodeKey)
	if err != nil {
		t.Error("Error:", err)
	}
	publicKey, err := convertX509PublicKeyToString(pubEncodeKey)
	if err != nil {
		t.Error("Error:", err)
	}
	if privKey != privateKey {
		t.Error("Error: Didn't convert well the Private Key")
	}
	if pubKey != publicKey {
		t.Error("Error: Didn't convert well the Public Key")
	}
}
