package endpoints

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"

	storage "iocscanner/src/db"
	"iocscanner/src/parse"
)

type domainRow struct {
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	ScannedAt int64    `json:"scanned_at"`
	Names     []string `json:"names"`
}

// from and before bound scanned_at as a half-open interval, both in epoch seconds and both
// optional. The dashboard picks days but sends instants: the boundary is midnight in the operator's
// timezone, which is the one the table's stamps are rendered in and not necessarily this process's.
func domains(ctx context.Context, needle, order string, from, before int64) ([]domainRow, error) {
	stored, err := storage.LoadCertificateScans(ctx)
	if err != nil {
		return nil, err
	}

	needle = strings.ToLower(strings.TrimSpace(needle))
	rows := []domainRow{}
	for _, scan := range stored {
		if scan.ScannedAt < from || (before > 0 && scan.ScannedAt >= before) {
			continue
		}
		var names []string
		for _, raw := range append([]string{scan.Subject}, strings.Split(scan.DNSNames, ",")...) {
			if name, ok := parse.CertName(raw); ok && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(scan.IP+" "+
			strconv.Itoa(scan.Port)+" "+strings.Join(names, " ")), needle) {
			continue
		}
		rows = append(rows, domainRow{IP: scan.IP, Port: scan.Port, ScannedAt: scan.ScannedAt, Names: names})
	}

	key, descending := sortOrder(order, "port", "name", "ip", "recent")
	primary := ordering(descending)
	byAddress := func(a, b domainRow) int {
		return parse.CompareIP(a.IP, b.IP)
	}
	// Newest first is the table's default listing, and what breaks ties under every other column
	// rather than whatever order the database happened to return.
	newest := func(a, b domainRow) int {
		return cmp.Or(cmp.Compare(b.ScannedAt, a.ScannedAt), byAddress(a, b), cmp.Compare(a.Port, b.Port))
	}
	switch key {
	case "port":
		slices.SortStableFunc(rows, func(a, b domainRow) int {
			return cmp.Or(primary(cmp.Compare(a.Port, b.Port)), newest(a, b))
		})
	case "name":
		slices.SortStableFunc(rows, func(a, b domainRow) int {
			return cmp.Or(primary(cmp.Compare(a.Names[0], b.Names[0])), newest(a, b))
		})
	case "ip":
		// The port stays ascending when the addresses are reversed: it breaks ties here rather
		// than being part of what was asked for.
		slices.SortStableFunc(rows, func(a, b domainRow) int {
			return cmp.Or(primary(byAddress(a, b)), cmp.Compare(a.Port, b.Port))
		})
	case "recent":
		// Ascending is oldest first, so this is the plain comparison and the default above is its
		// reverse, matching the host table's Last observed column.
		slices.SortStableFunc(rows, func(a, b domainRow) int {
			return cmp.Or(primary(cmp.Compare(a.ScannedAt, b.ScannedAt)), byAddress(a, b),
				cmp.Compare(a.Port, b.Port))
		})
	default:
		slices.SortStableFunc(rows, newest)
	}
	return rows, nil
}
