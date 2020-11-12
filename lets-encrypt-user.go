package lets_encrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"io/ioutil"
	"os"
)

type LetsEncryptUserConfig struct {
	Mail       string `mapstructure:"mail"`
	AccountDir string `mapstructure:"account_path"`
}

type LetsEncryptUser struct {
	Email        string
	Registration *registration.Resource
	KeyPair      *ecdsa.PrivateKey
}

// Init the Let's Encrypt user, if it' the first time, create every thing, and if the file already exist,
// use the existing account.
func InitLetsEncryptUser(config LetsEncryptUserConfig) (*LetsEncryptUser, error) {
	newUser := LetsEncryptUser{
		Email: config.Mail,
	}
	err := newUser.ReadExistingKeys(config.AccountDir)
	if err != nil {
		if err := newUser.CreateNewKeys(); err != nil {
			return nil, err
		}
		if err := newUser.WriteKeys(config.AccountDir); err != nil {
			return nil, err
		}
		if err := newUser.RegisterAccount(); err != nil {
			return nil, err
		}
		if err := newUser.SaveAccount(config.AccountDir); err != nil {
			return nil, err
		}
	}
	if err := newUser.ReadExistingRegistration(config.AccountDir); err != nil {
		return nil, err
	}
	return &newUser, nil
}

// Read the registration data from the json file saved before.
func (u *LetsEncryptUser) ReadExistingRegistration(AccountDir string) error {
	registrationBytes, err := ioutil.ReadFile(AccountDir + "/registration.json")
	if err != nil {
		return err
	}
	var UserRegistration registration.Resource
	err = json.Unmarshal(registrationBytes, &UserRegistration)
	if err != nil {
		return err
	}
	u.Registration = &UserRegistration
	return nil
}

func initLetsEncryptUserWithKeys(email string, keys *ecdsa.PrivateKey) LetsEncryptUser {
	return LetsEncryptUser{
		Email:   email,
		KeyPair: keys,
	}
}

// Return the LetsEncryptUser.Email.
func (u *LetsEncryptUser) GetEmail() string {
	return u.Email
}

// Return registration.Resource who represents all important information about a registration.
func (u LetsEncryptUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// Return crypto.PrivateKey.
func (u *LetsEncryptUser) GetPrivateKey() crypto.PrivateKey {
	return u.KeyPair
}

// Receive a ecdsa.PrivateKey and fill the object LetsEncryptUser with it.
func (u *LetsEncryptUser) SetPrivateKey(key *ecdsa.PrivateKey) {
	u.KeyPair = key
}

// Creates a new ACME client via lego.NewConfig and give it the object LetsEncryptUser ,
// use the URL to the Let's Encrypt staging or the production.
// Create the
func (u *LetsEncryptUser) RegisterAccount() error {
	config := lego.NewConfig(u)
	config.CADirURL = CADirURL
	config.Certificate.KeyType = CertificateKeyType
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	// Register this new account to the ACME server.
	u.Registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	return err
}

// Create a file named registration in json, marshal the registration and write it inside the file to save it.
func (u *LetsEncryptUser) SaveAccount(AccountDir string) error {
	registrationBytes, err := json.Marshal(u.Registration)
	if err != nil {
		return err
	}
	registrationFile, err := os.Create(AccountDir + "/registration.json")
	if err != nil {
		return err
	}
	_, err = registrationFile.Write(registrationBytes)
	if err != nil {
		return err
	}
	if err := registrationFile.Close(); err != nil {
		return err
	}
	return nil
}

// Use the public and private key pair already saved.
func (u *LetsEncryptUser) ReadExistingKeys(AccountDir string) error {
	privString, err := ioutil.ReadFile(AccountDir + "/privKey.pem")
	if err != nil {
		return err
	}
	pubString, err := ioutil.ReadFile(AccountDir + "/pubKey.pem")
	if err != nil {
		return err
	}
	u.KeyPair, _, err = stringToKey(string(privString), string(pubString))
	if err != nil {
		return err
	}
	return nil
}

// Generates a public and private key pair via ecdsa.GenerateKey.
func (u *LetsEncryptUser) CreateNewKeys() error {
	var err error
	u.KeyPair, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return err
}

// Convert those key pair into string to be able to save them into files just created.
func (u *LetsEncryptUser) WriteKeys(AccountDir string) error {

	// Convert this pub and priv key to string.
	stringPriv, err := convertX509PrivateKeyToString(u.KeyPair)
	if err != nil {
		return err
	}
	publicKey := &u.KeyPair.PublicKey
	stringPub, err := convertX509PublicKeyToString(publicKey)
	if err != nil {
		return err
	}

	pvFile, err := os.Create(AccountDir + "/privKey.pem")
	if err != nil {
		return err
	}
	puFile, err := os.Create(AccountDir + "/pubKey.pem")
	if err != nil {
		return err
	}
	defer pvFile.Close()
	defer puFile.Close()
	_, err = pvFile.WriteString(stringPriv)
	if err != nil {
		return err
	}
	_, err = puFile.WriteString(stringPub)
	if err != nil {
		return err
	}
	return nil
}

// Return the object LetsEncryptUser.
func (u *LetsEncryptUser) GetLEUser() registration.User {
	return u
}

// Take a ecdsa.PublicKey in argument and return it in string.
func convertX509PublicKeyToString(publicKey *ecdsa.PublicKey) (string, error) {
	if publicKey == nil {
		return "", errors.New("The given arg 'publicKey' is nil.")
	}
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncodedPub), nil
}

// Take a ecdsa.PrivateKey in argument and return it in string.
func convertX509PrivateKeyToString(privateKey *ecdsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", errors.New("The given arg 'privateKey' is nil.")
	}
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded), nil
}
