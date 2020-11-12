package pdns

import (
	"context"
	"errors"
	"github.com/mittwald/go-powerdns"
	"github.com/mittwald/go-powerdns/apis/zones"
	"strings"

	"github.com/DumesnyJeremy/lets-encrypt/providers/dns"
)

type InfoPDNS struct {
	Config dns.DNSServerConfig
	Client pdns.Client
}

func InitDNSServer(config dns.DNSServerConfig) (dns.DNSServer, error) {
	DNSServer, err := InitPDNS(config)
	if err != nil {
		return nil, err
	}
	return DNSServer, err
}

// Creates a new PowerDNS client and block until the PowerDNS API accepts HTTP requests.
func InitPDNS(DNSServer dns.DNSServerConfig) (*InfoPDNS, error) {
	client, err := pdns.New(pdns.WithBaseURL(DNSServer.URL), pdns.WithAPIKeyAuthentication(DNSServer.APIKey))
	if err != nil {
		return nil, err
	}
	// block until the PowerDNS API accepts HTTP requests
	err = client.WaitUntilUp(context.Background())
	if err != nil {
		return nil, err
	}
	return &InfoPDNS{
		Config: DNSServer,
		Client: client,
	}, nil
}

func doesZoneCoversDomain(domain string, zone zones.Zone) bool {
	return strings.Contains(domain, strings.TrimSuffix(zone.Name, "."))
}

// Lists known zones for a given serverID and return ture of false if a zone is found.
func (infopdns *InfoPDNS) IsAuthoritativeForDomain(domain string) bool {
	if infopdns.Client.Zones() == nil {
		return false
	}
	zonesDomain, err := infopdns.Client.Zones().ListZones(context.Background(), infopdns.Config.ServerID)
	if err != nil {
		return false
	}
	for _, zone := range zonesDomain {
		if doesZoneCoversDomain(domain, zone) {
			return true
		}
	}
	return false
}

// Lists known zones for a given serverID and if the zone covert the domain, return it.
func (infopdns *InfoPDNS) getZoneForDomain(domain string) (*zones.Zone, error) {
	if infopdns.Client.Zones() == nil {
		return nil, errors.New("Client.Zones() is nil.")
	}
	zonesDomain, err := infopdns.Client.Zones().ListZones(context.Background(), infopdns.Config.ServerID)
	if err != nil || zonesDomain == nil {
		return nil, err
	}
	for _, zone := range zonesDomain {
		if doesZoneCoversDomain(domain, zone) {
			return &zone, nil
		}
	}
	return nil, errors.New("Didn't found the zone ")
}

// Add a new set of records to a zone. Existing record sets for
// the exact name/type.
func (infopdns *InfoPDNS) AddTXTRecord(domain, name, value string) error {

	// Retrieve zone from domain name.
	zone, err := infopdns.getZoneForDomain(domain)
	if err != nil {
		return errors.New("Zone doesn't exist")
	}

	// Prepare a new TXT record set.
	recordSet := zones.ResourceRecordSet{
		Name:    name,
		Type:    "TXT",
		TTL:     60,
		Records: []zones.Record{{Content: value}},
	}

	// Add the record set to the appropriate zone.
	if err = infopdns.Client.Zones().AddRecordSetToZone(
		context.Background(),
		infopdns.Config.ServerID,
		zone.ID,
		recordSet,
	); err != nil {
		return err
	}

	return nil
}

// Removes a record set from a zone. The record set is matched by name and type.
func (infopdns *InfoPDNS) CleanTXTRecord(domain, name string) error {
	zone, err := infopdns.getZoneForDomain(domain)
	if err != nil {
		return err
	}
	if err := infopdns.Client.Zones().RemoveRecordSetFromZone(context.Background(),
		infopdns.Config.ServerID,
		zone.ID,
		name,
		"TXT"); err != nil {
		return err
	}
	return nil
}

// Returns the requested DNS server configuration.
func (infopdns *InfoPDNS) GetConfig() dns.DNSServerConfig {
	return infopdns.Config
}
