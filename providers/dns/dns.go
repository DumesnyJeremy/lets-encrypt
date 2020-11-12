package dns

import (
	"github.com/go-acme/lego/challenge/dns01"
)

// The 2 types of implementation to create the Let's Encrypt Challenge a certificate.
const ServerDNSTypePDNS = "pdns"
const ServerDNSTypeGandy = "gandy"

type DNSServer interface {
	IsAuthoritativeForDomain(domain string) bool
	GetConfig() DNSServerConfig
	AddTXTRecord(domain, name, value string) error
	CleanTXTRecord(domain, name string) error
}

type DNSProvider struct {
	DNSServer DNSServer
}

type DNSServerConfig struct {
	Name     string `mapstructure:"name"`
	Type     string `mapstructure:"type"`
	URL      string `mapstructure:"url"`
	APIKey   string `mapstructure:"api_key"`
	ServerID string `mapstructure:"server_id"`
}

// Fill the struct DNSProvider with the dnsServer object.
func NewDNSProvider(dnsServer DNSServer) DNSProvider {
	return DNSProvider{DNSServer: dnsServer}
}

// Grab TXT name and value from let's encrypt DNS server using keyAuth and add entry to our DNS server.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {

	fqdn, value := dns01.GetRecord(domain, keyAuth)

	if err := d.DNSServer.AddTXTRecord(domain, fqdn, "\""+value+"\""); err != nil {
		return err
	}
	return nil
}

// Retrieve FQDN from let's encrypt DNS server, or build it manually and remove TXT record.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {

	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	if fqdn == "" {
		fqdn = "_acme-challenge." + domain + "."
	}

	return d.DNSServer.CleanTXTRecord(domain, fqdn)
}
