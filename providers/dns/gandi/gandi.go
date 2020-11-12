package gandi

import (
	"github.com/prasmussen/gandi-api/client"
	"github.com/prasmussen/gandi-api/domain/zone"

	"github.com/DumesnyJeremy/lets-encrypt/providers/dns"
)

type InfoGandi struct {
	Config dns.DNSServerConfig
	Client *client.Client
}

func InitGandi(config dns.DNSServerConfig) (*InfoGandi, error) {
	gandiClient := client.New(config.APIKey, client.Production)
	return &InfoGandi{
		Config: config,
		Client: gandiClient,
	}, nil
}

func InitDNSServer(config dns.DNSServerConfig) (dns.DNSServer, error) {
	DNSServer, err := InitGandi(config)
	if err != nil {
		return nil, err
	}
	return DNSServer, nil
}

func (gandi *InfoGandi) IsAuthoritativeForDomain(domain string) bool {
	return true
}

func (gandi *InfoGandi) getZoneForDomain(domain string) *zone.Zone {
	zone.New(gandi.Client).List()
	return nil
}

func (gandi *InfoGandi) AddTXTRecord(domain, name, value string) error {
	return nil
}

func (gandi *InfoGandi) CleanTXTRecord(domain, name string) error {
	return nil
}

func (gandi *InfoGandi) GetConfig() dns.DNSServerConfig {
	return gandi.Config
}
