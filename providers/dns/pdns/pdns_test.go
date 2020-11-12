package pdns

import (
	"context"
	"errors"
	"github.com/mittwald/go-powerdns/apis/zones"
	"github.com/stretchr/testify/mock"
	"testing"

	"github.com/DumesnyJeremy/lets-encrypt/providers/dns"
	pdns_mocks "github.com/DumesnyJeremy/lets-encrypt/go-powerdns"
	pdns_zones_mocks "github.com/DumesnyJeremy/lets-encrypt/go-powerdns"
)

const domain = "blah.pangolin.re"

func TestWhenMockedMethodsReturns(t *testing.T) {

	// Set expectations on mockedClientObj.
	mockedClientObj := new(pdns_mocks.Client)
	mockedClientZonesObj := new(pdns_zones_mocks.Client)
	mockedClientObj.On("Zones", mock.Anything).Return(mockedClientZonesObj, nil)

	// Add expectations on mockedClientZonesObj.
	mockedClientZonesObj.On("ListZones", mock.Anything, mock.Anything).Return([]zones.Zone{{Name: "blah.pangolin.re."}}, nil)
	mockedClientZonesObj.On("AddRecordSetToZone", context.Background(), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedClientZonesObj.On("RemoveRecordSetFromZone", context.Background(), mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// Init struct with mocked external objects
	infopdns := createClient(mockedClientObj)

	// Call an actual method from 'infopdns'.
	if err := infopdns.AddTXTRecord(domain, "hello", "1234"); err != nil {
		t.Error("Error: ", err)
	}
	if err := infopdns.CleanTXTRecord(domain, "hello"); err != nil {
		t.Error("Error: ", err)
	}
	if _, err := infopdns.getZoneForDomain(domain); err != nil {
		t.Error("Error: ", err)
	}
	if found := infopdns.IsAuthoritativeForDomain(domain); found == false {
		t.Error("Error: Didn't found for this domain")
	}
	// Add expectations on local methods calls and usages.
	mockedClientObj.AssertExpectations(t)
	mockedClientZonesObj.AssertExpectations(t)
}

func TestWhenMockedMethodsReturnsErrors(t *testing.T) {
	// Set expectations on mockedClientObj.
	mockedClientObj := new(pdns_mocks.Client)
	mockedClientZonesObj := new(pdns_zones_mocks.Client)
	mockedClientObj.On("Zones", mock.Anything).Return(nil, errors.New("Couldn't found zones."))

	// Add expectations on mockedClientZonesObj.
	mockedClientZonesObj.On("ListZones", mock.Anything, mock.Anything).Return([]zones.Zone{{Name: "blah.pangolin.re."}}, errors.New("Zone doesn't exist."))
	mockedClientZonesObj.On("AddRecordSetToZone", context.Background(), mock.Anything, mock.Anything, mock.Anything).Return(errors.New("Couldn't add the given record."))
	mockedClientZonesObj.On("RemoveRecordSetFromZone", context.Background(), mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("Couldn't remove the given record."))
	infopdns := createClient(mockedClientObj)

	// Call an actual method from 'infopdns'.
	if err := infopdns.AddTXTRecord(domain, "hello", "1234"); err != nil {
		t.Error("Error: ", err)
	}
	if err := infopdns.CleanTXTRecord(domain, "hello"); err != nil {
		t.Error("Error: ", err)
	}
	if _, err := infopdns.getZoneForDomain(domain); err != nil {
		t.Error("Error: ", err)
	}
	if found := infopdns.IsAuthoritativeForDomain(domain); found == false {
		t.Error("Error: Didn't found for this domain")
	}

	// Add expectations on local methods calls and usages.
	mockedClientObj.AssertExpectations(t)
	mockedClientZonesObj.AssertExpectations(t)
}

func createClient(mockedClientObj *pdns_mocks.Client) InfoPDNS {
	return InfoPDNS{
		Config: dns.DNSServerConfig{
			Name:     "Example Serv",
			Type:     "pdns",
			URL:      "http://...:8080",
			APIKey:   "apikey",
			ServerID: "localhost",
		},
		Client: mockedClientObj,
	}
}
