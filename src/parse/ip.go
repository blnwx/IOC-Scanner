package parse

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// AddrOrZero returns the zero address for invalid stored or sortable values.
func AddrOrZero(value string) netip.Addr {
	addr, _ := netip.ParseAddr(value)
	return addr
}

// AnyContains reports whether any of the prefixes contains addr.
func AnyContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// DedupePrefixes returns the disjoint subset covering the same addresses. Sorting by address
// then mask puts a containing prefix ahead of everything nested inside it, so one pass drops the
// contained entries. Membership is unchanged. A prefix wholly inside another cannot change what
// AnyContains answers.
func DedupePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	kept, last := sorted[:0], netip.Prefix{}
	for _, prefix := range sorted {
		if last.Contains(prefix.Addr()) {
			continue
		}
		kept = append(kept, prefix)
		last = prefix
	}
	return kept
}

// HostCount counts the addresses the prefixes cover. The input is already disjoint (parsePrefixes
// dedupes), so this is a plain sum.
func HostCount(prefixes []netip.Prefix) int {
	total := 0
	for _, prefix := range prefixes {
		total += 1 << (32 - prefix.Bits())
	}
	return total
}

// Overlap returns the addresses two prefixes share. Prefixes either nest or are disjoint, so the
// shared part is whichever of the two is longer.
func Overlap(a, b netip.Prefix) (netip.Prefix, bool) {
	if !a.Overlaps(b) {
		return netip.Prefix{}, false
	}
	if b.Bits() > a.Bits() {
		return b, true
	}
	return a, true
}

// ParseIPv4Prefix accepts sources containing both address families. Valid IPv6 is skipped.
func ParseIPv4Prefix(raw string) (netip.Prefix, bool, error) {
	value := strings.TrimSpace(raw)
	if !strings.ContainsRune(value, '/') {
		value += "/32"
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("invalid IPv4 address or CIDR %q", raw)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, false, nil
	}
	return prefix.Masked(), true, nil
}

func ParsePrefix(raw string) (netip.Prefix, error) {
	prefix, ok, err := ParseIPv4Prefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !ok {
		return netip.Prefix{}, fmt.Errorf("IPv6 is not supported: %q", raw)
	}
	return prefix, nil
}

func ParseIPv4(value string) (netip.Addr, bool, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("invalid IP address %q", value)
	}
	return addr, addr.Is4(), nil
}

func ParsePort(value string) (uint16, bool) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	return uint16(port), err == nil && port != 0
}

func CanonicalAddr(value string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}
	return addr.String(), true
}

func AddrOf(value string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr, true
	}
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return addrPort.Addr(), true
	}
	return netip.Addr{}, false
}

// CompareIP parses rather than comparing strings, so .9 sorts before .10. Every stored address
// parses; an invalid one would sort as the zero address.
func CompareIP(a, b string) int {
	return AddrOrZero(a).Compare(AddrOrZero(b))
}
