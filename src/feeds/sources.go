package feeds

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"iocscanner/src/httpclient"
	"iocscanner/src/parse"
)

// fetchTweetFeed pulls the mixed IP, domain, and URL list.
func (f *Cache) fetchTweetFeed(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, TweetFeedURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return DecodeTweetFeed(body)
}

// fetchPhishingArmy pulls the hostname blocklist and reduces it to registrable domains.
func (f *Cache) fetchPhishingArmy(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, PhishingArmyURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return DecodeDomainFeed(body, PhishingArmySource, "phishing")
}

func (f *Cache) fetchURLHaus(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, URLHausURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return DecodeURLHaus(body)
}

func DecodeURLHaus(body io.Reader) ([]Indicator, error) {
	var records map[string][]struct {
		URL        string   `json:"url"`
		Status     string   `json:"url_status"`
		LastOnline string   `json:"last_online"`
		Threat     string   `json:"threat"`
		Tags       []string `json:"tags"`
	}
	if err := parse.JSON(body, &records); err != nil {
		return nil, err
	}
	if records == nil {
		return nil, errors.New("invalid data object")
	}
	var indicators []Indicator
	var validation FeedValidation
	for id, entries := range records {
		if strings.TrimSpace(id) == "" {
			validation.reject(errors.New("record has missing ID"))
			continue
		}
		for _, record := range entries {
			if record.Status == "" {
				validation.reject(errors.New("record has missing status"))
				continue
			}
			if record.Status != "online" {
				validation.valid++
				continue
			}
			if record.URL == "" || record.LastOnline == "" || record.Threat == "" {
				validation.reject(errors.New("online record has missing fields"))
				continue
			}
			value, ok, err := FeedURLValue(record.URL)
			if err != nil {
				validation.reject(err)
				continue
			}
			if !ok {
				validation.valid++
				continue
			}
			tag := record.Threat
			if len(record.Tags) > 0 {
				tag += " — " + strings.Join(record.Tags, ", ")
			}
			stamp := parseFeedTime(record.LastOnline)
			if stamp == "" {
				validation.reject(fmt.Errorf("invalid last-online date %q", record.LastOnline))
				continue
			}
			validation.valid++
			indicators = append(indicators, Indicator{Source: URLHausSource, Value: value, Tag: tag, FirstSeen: stamp, Link: "https://urlhaus.abuse.ch/url/" + url.PathEscape(id) + "/"})
		}
	}
	slices.SortFunc(indicators, func(a, b Indicator) int { return strings.Compare(a.Link, b.Link) })
	return validation.finish(indicators, nil)
}

func (f *Cache) fetchC2Intel(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, C2IntelURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return DecodeC2Intel(body)
}

func DecodeC2Intel(body io.Reader) ([]Indicator, error) {
	var indicators []Indicator
	validation, err := visitCSVRecords(body, func(record []string) error {
		if len(record) != 4 || strings.TrimSpace(record[1]) == "" {
			return errors.New("malformed record")
		}
		domain, ok := parse.RegistrableDomain(record[0])
		if !ok {
			return fmt.Errorf("invalid domain %q", record[0])
		}
		addr, ok, err := parse.ParseIPv4(record[3])
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		ioc := strings.TrimSpace(record[1])
		indicators = append(indicators,
			Indicator{Source: C2IntelSource, Value: addr.String(), Tag: "IP — " + ioc + " — domain " + domain, FirstSeen: "", Link: ""},
			Indicator{Source: C2IntelSource, Value: domain, Tag: "Domain — " + ioc + " — IP " + addr.String(), FirstSeen: "", Link: ""})
		return nil
	})
	return validation.finish(indicators, err)
}

func (f *Cache) fetchThreatViewC2(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, ThreatViewC2URL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return DecodeThreatViewC2(body)
}

func DecodeThreatViewC2(body io.Reader) ([]Indicator, error) {
	var indicators []Indicator
	validation, err := visitCSVRecords(body, func(record []string) error {
		if len(record) != 6 || strings.TrimSpace(record[1]) == "" {
			return errors.New("malformed record")
		}
		// Rows keyed by a domain rather than an address are a record class this feed publishes.
		// The index matches on an address, so they are ignored rather than counted as damage.
		addr, ok, _ := parse.ParseIPv4(record[0])
		if !ok {
			return nil
		}
		stamp := parseFeedTime(record[1])
		if stamp == "" {
			return fmt.Errorf("invalid detection date %q", record[1])
		}
		tag := "C2"
		host := strings.TrimSpace(record[2])
		if domain, ok := parse.RegistrableDomain(host); ok {
			indicators = append(indicators,
				Indicator{Source: ThreatViewSource, Value: addr.String(), Tag: tag, FirstSeen: stamp, Link: ""},
				Indicator{Source: ThreatViewSource, Value: domain, Tag: tag, FirstSeen: stamp, Link: ""})
		} else {
			indicators = append(indicators, Indicator{Source: ThreatViewSource, Value: addr.String(), Tag: tag, FirstSeen: stamp, Link: ""})
		}
		return nil
	})
	return validation.finish(indicators, err)
}

func (f *Cache) fetchThreatViewDomains(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, ThreatViewDomainURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return DecodeDomainFeed(body, ThreatViewSource, "Phishing/Malware")
}

func DecodeDomainFeed(body io.Reader, source, tag string) ([]Indicator, error) {
	var indicators []Indicator
	var validation FeedValidation
	seen := map[string]bool{}
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		domain, ok := parse.RegistrableDomain(value)
		if !ok {
			validation.reject(fmt.Errorf("invalid domain %q", value))
			continue
		}
		validation.valid++
		if !seen[domain] {
			seen[domain] = true
			indicators = append(indicators, Indicator{Source: source, Value: domain, Tag: tag, FirstSeen: "", Link: ""})
		}
	}
	return validation.finish(indicators, scanner.Err())
}

func (f *Cache) fetchThreatViewURLs(ctx context.Context) ([]Indicator, error) {
	body, err := httpclient.Get(ctx, f.Client, ThreatViewURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return DecodeThreatViewURLs(body)
}

func DecodeThreatViewURLs(body io.Reader) ([]Indicator, error) {
	var indicators []Indicator
	var validation FeedValidation
	seen := map[string]bool{}
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		normalized, ok, err := FeedURLValue(value)
		if err != nil {
			validation.reject(err)
			continue
		}
		validation.valid++
		if ok && !seen[normalized] {
			seen[normalized] = true
			indicators = append(indicators, Indicator{Source: ThreatViewSource, Value: normalized, Tag: "Phishing/Malware", FirstSeen: "", Link: ""})
		}
	}
	return validation.finish(indicators, scanner.Err())
}

// DecodeTweetFeed parses one TweetFeed list body into indicators.
func DecodeTweetFeed(body io.Reader) ([]Indicator, error) {
	var records *[]struct {
		Date  string   `json:"date"`
		User  string   `json:"user"`
		Type  string   `json:"type"`
		Value string   `json:"value"`
		Tags  []string `json:"tags"`
		Tweet string   `json:"tweet"`
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
		// Tags are optional in upstream data; the other fields are not.
		if record.Date == "" || record.User == "" || record.Type == "" || record.Value == "" {
			validation.reject(errors.New("record has missing fields"))
			continue
		}
		value := strings.ToLower(strings.TrimSpace(record.Value))
		switch record.Type {
		case "ip":
			addr, ok, err := parse.ParseIPv4(record.Value)
			if err != nil {
				validation.reject(err)
				continue
			}
			if !ok {
				validation.valid++
				continue
			}
			value = addr.String()
		case "url":
			parsed, err := url.Parse(value)
			if err != nil || parsed.Hostname() == "" {
				validation.reject(fmt.Errorf("invalid URL %q", record.Value))
				continue
			}
			if normalized, isIP, err := urlIPValue(parsed); isIP {
				if err != nil {
					validation.reject(fmt.Errorf("invalid URL %q", record.Value))
					continue
				}
				if normalized == "" {
					validation.valid++
					continue
				}
				value = normalized
				break
			}
			value = parsed.Hostname()
			fallthrough
		case "domain":
			// Reject values that cannot match a certificate name.
			value = parse.NormalizeName(value)
			if value == "" || strings.ContainsAny(value, "/:@ ") {
				validation.reject(fmt.Errorf("invalid domain %q", record.Value))
				continue
			}
		default:
			validation.valid++
			continue
		}
		validation.valid++
		indicators = append(indicators, Indicator{Source: "tweetfeed", Value: value, Tag: record.Type + " — " + tweetFeedTag(record.Tags, record.User), FirstSeen: parseFeedTime(record.Date), Link: validTweetLink(record.Tweet)})
	}
	return validation.finish(indicators, nil)
}

func validTweetLink(value string) string {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" ||
		(host != "x.com" && host != "twitter.com" && !strings.HasSuffix(host, ".x.com") &&
			!strings.HasSuffix(host, ".twitter.com")) {
		return ""
	}
	return value
}

// tweetFeedTag uses hashtags as the reason, falling back to the poster.
func tweetFeedTag(tags []string, user string) string {
	trimmed := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag = strings.TrimPrefix(strings.TrimSpace(tag), "#"); tag != "" {
			trimmed = append(trimmed, tag)
		}
	}
	if len(trimmed) == 0 {
		return "@" + user
	}
	return strings.Join(trimmed, ", ")
}
