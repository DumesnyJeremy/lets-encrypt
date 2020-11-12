package lets_encrypt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"os"

	"github.com/DumesnyJeremy/lets-encrypt/providers/dns"
)

type LetsEncryptCertConfig struct {
	CertificateDir string `mapstructure:"certificate_dir_path"`
}

type LetsEncrypt struct {
	Client               *lego.Client
	User                 registration.User
	CertificatesRootPath string
}

const (
	//CADirURL = lego.LEDirectoryProduction
	CADirURL           = lego.LEDirectoryStaging
	CertificateKeyType = certcrypto.RSA2048
)

// Creates a new ACME client on behalf of the user.
// The client will depend on the ACME directory located at CADirURL.
func InitLetsEncrypt(CertificatesRootPath string, user registration.User) (LetsEncrypt, error) {

	leConfig := lego.NewConfig(user)
	leConfig.CADirURL = CADirURL
	leConfig.Certificate.KeyType = CertificateKeyType
	client, err := lego.NewClient(leConfig)
	if err != nil {
		return LetsEncrypt{}, err
	}

	return LetsEncrypt{
		CertificatesRootPath: CertificatesRootPath,
		User:                 user,
		Client:               client,
	}, nil
}

// SetDNS01Provider specifies a custom provider that can solve the given DNS-01 challenge.
func (LE *LetsEncrypt) SetDNSProvider(dnsProvider dns.DNSProvider) error {
	if err := LE.Client.Challenge.SetDNS01Provider(&dnsProvider); err != nil {
		return err
	}
	return nil
}

// Tries to obtain a certificate using all domains passed into it.
func (LE *LetsEncrypt) AskCertificate(fullDomainName string) error {
	request := certificate.ObtainRequest{
		Domains: []string{fullDomainName},
		Bundle:  true,
	}
	certificates, err := LE.Client.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	if err := LE.addCertificateIntoFolder(certificates, fullDomainName); err != nil {
		return err
	}
	return nil
}

// Split the certificate in two, the key and the certificate to write them in different files.
func (LE *LetsEncrypt) addCertificateIntoFolder(certificates *certificate.Resource, fullDomainName string) error {
	nameFolder := LE.CertificatesRootPath + "/" + fullDomainName
	if _, err := os.Stat(nameFolder); os.IsNotExist(err) {
		if err := os.Mkdir(nameFolder, os.ModePerm); err != nil {
			return err
		}
	}
	PrivateKeyFile, err := os.Create(nameFolder + "/" + fullDomainName + ".key")
	if err != nil {
		return err
	}
	CertifFile, err := os.Create(nameFolder + "/" + fullDomainName + ".crt")
	if err != nil {
		return err
	}

	if err := writeCertifIntoFile(PrivateKeyFile, CertifFile, certificates); err != nil {
		return err
	}

	return nil
}

func writeCertifIntoFile(PrivateKeyFile *os.File, CertifFile *os.File, certificates *certificate.Resource) error {

	// Clear file
	if err := PrivateKeyFile.Truncate(0); err != nil {
		return err
	}
	if err := CertifFile.Truncate(0); err != nil {
		return err
	}

	// Write into file
	_, err := PrivateKeyFile.Write(certificates.PrivateKey)
	if err != nil {
		return err
	}
	_, err = CertifFile.Write(certificates.Certificate)
	if err != nil {
		return err
	}

	if err := CertifFile.Close(); err != nil {
		return err
	}
	if err := PrivateKeyFile.Close(); err != nil {
		return err
	}

	return nil
}

// Take the Private and Public string Key in arg and return the 2 ecdsa Keys.
func stringToKey(pemEncodedPriv string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))
	if blockPriv == nil {
		return nil, nil, errors.New("PrivateBlock is nil.")
	}
	x509Encoded := blockPriv.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, nil, err
	}

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	if blockPub == nil {
		return nil, nil, errors.New("PublicBlock is nil.")
	}
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, nil, err
	}
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey, nil
}
