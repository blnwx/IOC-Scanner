package feeds

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"iocscanner/src/parse"
)

// FeedValidation counts a decode as it runs and is the error it reports. A response with both
// good and bad records returns its indicators alongside this, so a partial feed is accepted
// rather than discarded; errors.As is how a caller tells that apart from a complete failure.
type FeedValidation struct {
	valid, Skipped int
	first          error
}

func (v *FeedValidation) Error() string {
	return fmt.Sprintf("skipped %d invalid records (first: %v)", v.Skipped, v.first)
}

func (v *FeedValidation) reject(err error) {
	v.Skipped++
	if v.first == nil {
		v.first = err
	}
}

func (v *FeedValidation) finish(indicators []Indicator, readErr error) ([]Indicator, error) {
	if readErr != nil {
		return nil, readErr
	}
	if v.Skipped == 0 {
		return indicators, nil
	}
	if v.valid == 0 {
		return nil, fmt.Errorf("no valid records: %w", v.first)
	}
	return indicators, v
}

// visitCSVRecords isolates physical rows so a broken quote cannot consume later records.
func visitCSVRecords(body io.Reader, visit func([]string) error) (FeedValidation, error) {
	var validation FeedValidation
	scanner := bufio.NewScanner(body)
	// csv.Reader had no line limit; bufio.Scanner defaults to 64KB and would drop the whole feed
	// on one long row rather than the row.
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		reader := csv.NewReader(strings.NewReader(line))
		reader.FieldsPerRecord = -1
		record, err := reader.Read()
		if err == nil {
			err = visit(record)
		}
		if err != nil {
			validation.reject(err)
		} else {
			validation.valid++
		}
	}
	return validation, scanner.Err()
}

// urlIPValue canonicalizes an IP URL while leaving domain handling to each feed's contract.
func urlIPValue(parsed *url.URL) (string, bool, error) {
	addr, ok, err := parse.ParseIPv4(parsed.Hostname())
	if err != nil {
		return "", false, nil
	}
	if !ok {
		return "", true, nil
	}
	if parsed.Port() == "" {
		return addr.String(), true, nil
	}
	port, ok := parse.ParsePort(parsed.Port())
	if !ok {
		return "", true, errors.New("invalid port")
	}
	return netip.AddrPortFrom(addr, port).String(), true, nil
}

// FeedURLValue keeps an explicit IPv4 port and reduces domains to their registrable form.
func FeedURLValue(raw string) (string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", false, fmt.Errorf("invalid URL %q", raw)
	}
	if value, isIP, err := urlIPValue(parsed); isIP {
		if err != nil {
			return "", false, fmt.Errorf("invalid URL %q", raw)
		}
		return value, value != "", nil
	}
	host := strings.ToLower(parsed.Hostname())
	domain, ok := parse.RegistrableDomain(host)
	if !ok {
		return "", false, fmt.Errorf("invalid URL domain %q", host)
	}
	return domain, true, nil
}

// newIndicator builds an indicator from a separate host and port, skipping IPv6 (ok=false)
// and erroring on junk.
func newIndicator(source, host string, port uint16, tag, firstSeen string) (Indicator, bool, error) {
	addr, ok, err := parse.ParseIPv4(host)
	if err != nil {
		return Indicator{}, false, err
	}
	if !ok {
		return Indicator{}, false, nil
	}
	return Indicator{Source: source, Value: netip.AddrPortFrom(addr, port).String(), Tag: tag, FirstSeen: parseFeedTime(firstSeen), Link: ""}, true, nil
}

// parseFeedTime normalises a feed timestamp to RFC3339. Most feeds treat it as optional; parsers
// whose date is required validate the empty result themselves.
func parseFeedTime(value string) string {
	value = strings.TrimSpace(value)
	for _, layout := range feedTimeLayouts {
		if stamp, err := time.Parse(layout, value); err == nil {
			return stamp.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

func FeedDateLabel(source string) string {
	switch source {
	case URLHausSource:
		return "last_online"
	case ThreatViewSource:
		return "detected"
	default:
		return "first_seen"
	}
}
