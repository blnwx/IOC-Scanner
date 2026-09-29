package parse

import (
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var domainName = regexp.MustCompile(`^(\*\.)?([a-z0-9_-]+\.)+([a-z]{2,}|xn--[a-z0-9-]+)$`)

func NormalizeName(raw string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "*."), ".")
}

func CertName(raw string) (string, bool) {
	// Unlike matching, the domain inventory deliberately displays a certificate's wildcard.
	name := strings.Trim(strings.ToLower(strings.TrimSpace(raw)), ".")
	return name, domainName.MatchString(name)
}

func RegistrableDomain(raw string) (string, bool) {
	name, ok := CertName(NormalizeName(raw))
	if !ok {
		return "", false
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return name, true
	}
	return domain, true
}
