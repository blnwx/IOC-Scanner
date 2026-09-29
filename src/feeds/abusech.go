package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"iocscanner/src/httpclient"
	"iocscanner/src/parse"
	targetcfg "iocscanner/src/targets"
)

// FetchThreatFox pulls the ThreatFox IOC API and returns its IPv4 ip:port hits.
func (f *Cache) FetchThreatFox(ctx context.Context) ([]Indicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ThreatFoxURL, strings.NewReader(`{"query":"get_iocs","days":7}`))
	if err != nil {
		return nil, err
	}
	cfg, _ := targetcfg.Current.Config()
	req.Header.Set("Auth-Key", cfg.Feeds.ThreatFoxAuthKey)
	req.Header.Set("Content-Type", "application/json")
	body, err := httpclient.Body(f.Client, req)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	// Data stays raw until the status is checked. A failed query returns it as a string.
	var response struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := parse.JSON(body, &response); err != nil {
		return nil, err
	}
	// The API signals problems in-band via query_status.
	if response.Status != "ok" {
		return nil, fmt.Errorf("query status %q", response.Status)
	}
	var records *[]struct {
		ID         string `json:"id"`
		IOC        string `json:"ioc"`
		ThreatType string `json:"threat_type"`
		IOCType    string `json:"ioc_type"`
		Malware    string `json:"malware"`
		FirstSeen  string `json:"first_seen"`
		Confidence *int   `json:"confidence_level"`
	}
	if err := json.Unmarshal(response.Data, &records); err != nil || records == nil {
		return nil, errors.New("invalid data array")
	}

	indicators := make([]Indicator, 0, len(*records))
	var validation FeedValidation
	for _, record := range *records {
		// Every record must be fully populated (trust-boundary check).
		if record.ID == "" || record.IOC == "" || record.ThreatType == "" || record.IOCType == "" || record.Malware == "" {
			validation.reject(errors.New("record has missing fields"))
			continue
		}
		// An out-of-range score is dropped. The indicator itself is still good.
		if record.Confidence != nil && (*record.Confidence < 0 || *record.Confidence > 100) {
			record.Confidence = nil
		}
		// Keep every threat type, but only ip:port entries. The index and feedHitsInScope can
		// only match on an address.
		if record.IOCType != "ip:port" {
			validation.valid++
			continue
		}
		addrPort, err := netip.ParseAddrPort(strings.TrimSpace(record.IOC))
		if err != nil || addrPort.Port() == 0 {
			validation.reject(fmt.Errorf("invalid IP:port %q", record.IOC))
			continue
		}
		validation.valid++
		if addrPort.Addr().Is4() {
			indicators = append(indicators, Indicator{Source: "threatfox", Value: addrPort.String(), Tag: record.Malware,
				FirstSeen: parseFeedTime(record.FirstSeen), Link: "https://threatfox.abuse.ch/ioc/" + url.PathEscape(record.ID) + "/",
				ConfidenceLevel: record.Confidence})
		}
	}
	return validation.finish(indicators, nil)
}

// FetchFeodo pulls the Feodo Tracker JSON blocklist and returns its IPv4 ip:port hits.
func (f *Cache) FetchFeodo(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, FeodoURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var records *[]struct {
		IP        string `json:"ip_address"`
		Port      uint16 `json:"port"`
		Malware   string `json:"malware"`
		FirstSeen string `json:"first_seen"`
	}
	if err := parse.JSON(body, &records); err != nil {
		return nil, err
	}
	if records == nil {
		return nil, errors.New("invalid data array")
	}
	indicators := make([]Indicator, 0, len(*records))
	var validation FeedValidation
	for _, record := range *records {
		// Reject partial records, then keep IPv4 (newIndicator skips IPv6).
		if record.IP == "" || record.Port == 0 || record.Malware == "" {
			validation.reject(errors.New("record has missing fields"))
			continue
		}
		found, ok, err := newIndicator("feodo", record.IP, record.Port, record.Malware, record.FirstSeen)
		if err != nil {
			validation.reject(err)
			continue
		}
		validation.valid++
		if ok {
			indicators = append(indicators, found)
		}
	}
	return validation.finish(indicators, nil)
}

// FetchSSLBL pulls the SSLBL botnet-C2 IP blocklist (CSV) and returns its IPv4 ip:port hits.
func (f *Cache) FetchSSLBL(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, SSLBLIPURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var indicators []Indicator
	validation, err := visitCSVRecords(body, func(record []string) error {
		// Each row is Firstseen,DstIP,DstPort.
		if len(record) != 3 || strings.TrimSpace(record[0]) == "" {
			return errors.New("malformed record")
		}
		port, ok := parse.ParsePort(record[2])
		if !ok {
			return fmt.Errorf("invalid port %q", record[2])
		}
		found, ok, err := newIndicator("sslbl", record[1], port, "botnet_cc", record[0])
		if err != nil {
			return err
		}
		if ok {
			indicators = append(indicators, found)
		}
		return nil
	})
	return validation.finish(indicators, err)
}

// FetchSSLBLCerts pulls the SSLBL blacklist of botnet-C2 certificate SHA-1 fingerprints. This
// is a different file from the IP blocklist above, and the only feed a collected cert can match.
func (f *Cache) FetchSSLBLCerts(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, SSLBLCertURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var indicators []Indicator
	validation, err := visitCSVRecords(body, func(record []string) error {
		// Each row is Firstseen,SHA1,Listingreason.
		if len(record) != 3 || strings.TrimSpace(record[2]) == "" {
			return errors.New("malformed record")
		}
		// Lowercased so it matches the hex the scanner computes from a collected cert.
		fingerprint := strings.ToLower(strings.TrimSpace(record[1]))
		if len(fingerprint) != 40 {
			return fmt.Errorf("invalid SHA-1 fingerprint %q", record[1])
		}
		indicators = append(indicators, Indicator{Source: "sslbl_cert", Value: fingerprint, Tag: strings.TrimSpace(record[2]), FirstSeen: parseFeedTime(record[0]), Link: ""})
		return nil
	})
	return validation.finish(indicators, err)
}
