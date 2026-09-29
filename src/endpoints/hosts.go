package endpoints

import (
	"cmp"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	"iocscanner/src/parse"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

const (
	// maxPortsShown caps the port records carried per host. PortCount still reports the real figure.
	maxPortsShown = 50
	maxPageSize   = 200
)

// hostsResponse is one page of the host table. The tallies count everything observed rather than
// the filtered page, so searching does not move the summary figures.
type hostsResponse struct {
	InScope int `json:"in_scope"`
	// Scanned is retained for API compatibility and counts hosts with a scan or feed match.
	Scanned int                `json:"scanned"`
	LiveTLS int                `json:"live_tls"`
	High    int                `json:"high"`
	Low     int                `json:"low"`
	Acked   int                `json:"acked"`
	Matched int                `json:"matched"`
	Page    int                `json:"page"`
	Pages   int                `json:"pages"`
	Hosts   []scanner.HostView `json:"hosts"`
	// Configured is false only on the feed-only table with no feed_only_targets_file set, so the
	// page can say the feature is off rather than show an empty result.
	Configured bool `json:"configured"`
}

// handleHosts serves the host table: everything found so far, filtered, sorted and paged.
func handleHosts(w http.ResponseWriter, r *http.Request) {
	handleHostsMode(w, r, false)
}

func handleFeedOnlyHosts(w http.ResponseWriter, r *http.Request) {
	handleHostsMode(w, r, true)
}

func handleHostsMode(w http.ResponseWriter, r *http.Request, feedOnly bool) {
	// A full scan of the table and a re-check of every row, per request. Free at this size, and
	// it keeps the flagging rules in one place instead of restating them as SQL. Past roughly
	// 50k rows this wants a short-lived memo of the result, or paging pushed down into SQL.
	hosts, summary, err := scanner.Findings(r.Context(), hostProjection(feedOnly))
	if err != nil {
		slog.Error("dashboard host query failed", "err", err)
		http.Error(w, "cannot read the scan database", http.StatusInternalServerError)
		return
	}
	cfg, scope := targetcfg.Current.Config()
	inScope, configured := scope.Scannable, true
	if feedOnly {
		inScope, configured = scope.FeedOnlyScannable, cfg.Scan.FeedOnlyTargetsFile != ""
	}
	body := hostsResponse{InScope: inScope, Scanned: len(hosts),
		LiveTLS: summary.LiveTLSHosts, High: summary.High, Low: summary.Low,
		Acked: summary.Acked, Configured: configured}

	query := r.URL.Query()
	// The band filter is a set of checkboxes, so it arrives as one parameter per ticked box and
	// the ticked ones are the ones shown. No parameter at all is no filter, which is what a
	// hand-typed URL and every link that predates the checkboxes mean.
	wanted, filtered := query["band"], query.Has("band")
	origin := query.Get("origin")
	// An unparseable port is no filter rather than an error. The field is a free-text box.
	port, err := strconv.Atoi(query.Get("port"))
	if err != nil {
		port = 0
	}
	needle := strings.ToLower(strings.TrimSpace(query.Get("q")))
	hosts = slices.DeleteFunc(hosts, func(host scanner.HostView) bool {
		// "clean" is the name the dashboard gives the empty band; the rest are the band itself.
		if filtered && !slices.Contains(wanted, cmp.Or(host.Band, "clean")) {
			return true
		}
		if !feedOnly && (origin == "manual" && !host.Manual || origin == "scheduled" && host.Manual) {
			return true
		}
		if !feedOnly && port != 0 && !slices.ContainsFunc(host.Ports, func(p scanner.PortView) bool { return p.Port == port }) {
			return true
		}
		return needle != "" && !strings.Contains(searchable(host), needle)
	})
	body.Matched = len(hosts)
	sortHosts(hosts, query.Get("sort"))

	// Capped so a handcrafted URL cannot ask for the whole table in one response. positive
	// already rejects zero and negatives, so there is no floor to impose beyond that.
	size := min(positive(query.Get("size"), 50), maxPageSize)
	body.Pages = max(1, (len(hosts)+size-1)/size)
	body.Page = min(positive(query.Get("page"), 1), body.Pages)
	start := (body.Page - 1) * size
	// Sliced, not copied. hosts is this request's own slice.
	body.Hosts = hosts[start:min(start+size, len(hosts))]
	// A tarpit answers on every port, and one of those hosts would otherwise put tens of
	// thousands of records in the response and as many cells in one table row. Truncated here,
	// after the filters and the sort, so searching a port on such a host still finds it.
	//
	// The reason the host matched has to survive the cut, or the row arrives with nothing to
	// explain it. The filtered port and anything carrying a signal go to the front first, and
	// the rest keep their order behind them.
	for i, host := range body.Hosts {
		if len(host.Ports) <= maxPortsShown {
			continue
		}
		// A clone: these portView slices come from hostViews and are shared with nothing here,
		// but reordering the caller's backing array to build one response is not worth the doubt.
		ports := slices.Clone(host.Ports)
		slices.SortStableFunc(ports, func(a, b scanner.PortView) int {
			return cmp.Compare(portRank(a, port), portRank(b, port))
		})
		body.Hosts[i].Ports = ports[:maxPortsShown]
	}
	writeJSON(w, body)
}

// handleAck toggles one host or explicitly sets a page of hosts. The address must already be
// present in the host table, including feed-only matches and manual scans outside the current scope.
func handleAck(w http.ResponseWriter, r *http.Request) {
	// A cross-origin form post cannot set this header, so requiring it makes the browser preflight
	// the request and refuse it. Nothing else here would stop a page the operator happened to have
	// open from acknowledging their findings for them.
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "expected a JSON body", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		IP    string   `json:"ip"`
		IPs   []string `json:"ips"`
		Acked *bool    `json:"acked"`
	}
	if err := parse.JSON(http.MaxBytesReader(w, r.Body, 64<<10), &body); err != nil {
		http.Error(w, "cannot read the request body", http.StatusBadRequest)
		return
	}
	if body.IPs != nil || body.Acked != nil {
		if body.IP != "" || body.Acked == nil || len(body.IPs) == 0 || len(body.IPs) > maxPageSize {
			http.Error(w, "bulk acknowledgement requires 1 to 200 addresses and acked", http.StatusBadRequest)
			return
		}
		handleBulkAck(w, r, body.IPs, *body.Acked)
		return
	}
	ip, ok := parse.CanonicalAddr(body.IP)
	if !ok {
		http.Error(w, "not an address", http.StatusBadRequest)
		return
	}
	// The whole table, to acknowledge one host. It is what the dashboard already does per request,
	// and it means the signature stored here is produced by the code that later checks it rather
	// than by a second copy of the rules.
	feedOnly, ok := feedOnlySelector(r)
	if !ok {
		http.Error(w, "unknown target selector", http.StatusBadRequest)
		return
	}
	hosts, _, err := scanner.Findings(r.Context(), hostProjection(feedOnly))
	if err != nil {
		slog.Error("dashboard ack query failed", "err", err)
		http.Error(w, "cannot read the scan database", http.StatusInternalServerError)
		return
	}
	index := slices.IndexFunc(hosts, func(host scanner.HostView) bool { return host.IP == ip })
	if index < 0 {
		http.Error(w, "no such host", http.StatusNotFound)
		return
	}
	host := hosts[index]
	// A band of "ack" means the acknowledgement still describes the host, so there is a live one to
	// clear. A stale row bands the host by what is wrong with it instead, and the acknowledgement
	// below overwrites the row rather than clearing it — which is what the operator asked for.
	if host.Band == "ack" {
		if err := storage.DeleteAck(r.Context(), host.IP); err != nil {
			slog.Error("clearing an acknowledgement failed", "ip", host.IP, "err", err)
			http.Error(w, "cannot write to the scan database", http.StatusInternalServerError)
			return
		}
		slog.Info("acknowledgement cleared", "ip", host.IP)
		writeJSON(w, map[string]any{"acked": false})
		return
	}
	row := storage.Ack{IP: host.IP, AckedAt: time.Now().Unix(), Signature: scanner.AckSignature(host)}
	if err := storage.SaveAck(r.Context(), row); err != nil {
		slog.Error("saving an acknowledgement failed", "ip", host.IP, "err", err)
		http.Error(w, "cannot write to the scan database", http.StatusInternalServerError)
		return
	}
	slog.Info("host acknowledged", "ip", host.IP, "band", host.Band)
	writeJSON(w, map[string]any{"acked": true, "acked_at": row.AckedAt})
}

func handleBulkAck(w http.ResponseWriter, r *http.Request, rawIPs []string, acked bool) {
	ips := make([]string, 0, len(rawIPs))
	for _, raw := range rawIPs {
		ip, ok := parse.CanonicalAddr(raw)
		if !ok {
			http.Error(w, "not an address", http.StatusBadRequest)
			return
		}
		if !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	feedOnly, ok := feedOnlySelector(r)
	if !ok {
		http.Error(w, "unknown target selector", http.StatusBadRequest)
		return
	}
	hosts, _, err := scanner.Findings(r.Context(), hostProjection(feedOnly))
	if err != nil {
		slog.Error("dashboard bulk ack query failed", "err", err)
		http.Error(w, "cannot read the scan database", http.StatusInternalServerError)
		return
	}
	byIP := make(map[string]scanner.HostView, len(hosts))
	for _, host := range hosts {
		byIP[host.IP] = host
	}
	for _, ip := range ips {
		if _, ok := byIP[ip]; !ok {
			http.Error(w, "no such host", http.StatusNotFound)
			return
		}
	}
	// Hosts already in the requested state are left alone, so the request is idempotent. The count
	// reported back is the rows that actually change, not the addresses asked about.
	changed := 0
	if !acked {
		for _, ip := range ips {
			if byIP[ip].Band == "ack" {
				changed++
			}
		}
		err = storage.DeleteAcks(r.Context(), ips)
	} else {
		now := time.Now().Unix()
		rows := make([]storage.Ack, 0, len(ips))
		for _, ip := range ips {
			if host := byIP[ip]; host.Band != "ack" {
				rows = append(rows, storage.Ack{IP: ip, AckedAt: now, Signature: scanner.AckSignature(host)})
			}
		}
		changed = len(rows)
		err = storage.SaveAcks(r.Context(), rows)
	}
	if err != nil {
		slog.Error("bulk acknowledgement failed", "acked", acked, "hosts", len(ips), "err", err)
		http.Error(w, "cannot write to the scan database", http.StatusInternalServerError)
		return
	}
	slog.Info("bulk acknowledgement updated", "acked", acked, "hosts", changed)
	writeJSON(w, map[string]any{"acked": acked, "updated": changed})
}

// hostProjection maps the ?target selector onto the projection it names.
func hostProjection(feedOnly bool) scanner.Projection {
	if feedOnly {
		return scanner.FeedOnlyMatches
	}
	return scanner.ActiveOpen
}

// searchable flattens a host into the one string the search box matches against: its address,
// every open port, every reason, and the certificate's text fields. Validity dates are left out.
// They are stored as epoch seconds, and formatting every one of them per request to match a date
// the operator can already sort and read off the table is not worth the pass.
func searchable(host scanner.HostView) string {
	var text strings.Builder
	text.WriteString(host.IP)
	for _, signal := range host.Signals {
		text.WriteString(" " + signal.Source + " " + signal.Tag + " " + signal.Value)
	}
	for _, port := range host.Ports {
		text.WriteString(" " + strconv.Itoa(port.Port) + " " + port.Subject + " " + port.Issuer +
			" " + port.DNSNames + " " + port.Fingerprint + " " + port.SerialNumber +
			" " + port.SignatureAlgorithm + " " + port.JARM)
		// Stored as a bool, so it is only searchable if the word is written out.
		if port.SelfSigned {
			text.WriteString(" self-signed")
		}
	}
	return strings.ToLower(text.String())
}

// sourceCount is how many distinct reasons a host shows. The dashboard collapses every signal from
// one source into a single badge, so the reason sort orders by that badge count, not raw signals.
func sourceCount(signals []feeds.Indicator) int {
	var sources []string
	for _, signal := range signals {
		if !slices.Contains(sources, signal.Source) {
			sources = append(sources, signal.Source)
		}
	}
	return len(sources)
}

// sortHosts orders the table. Anything unrecognised uses the deterministic
// most-recently-observed default.
func sortHosts(hosts []scanner.HostView, order string) {
	key, descending := sortOrder(order, "ip", "ports", "reasons", "band", "recent")
	primary := ordering(descending)
	address := func(a, b scanner.HostView) int {
		return parse.CompareIP(a.IP, b.IP)
	}
	switch key {
	case "ip":
		slices.SortStableFunc(hosts, func(a, b scanner.HostView) int {
			return primary(address(a, b))
		})
	case "ports":
		// Ties fall back to recency, the table's baseline order, then to the address, rather than
		// to whatever order the database happened to return.
		slices.SortStableFunc(hosts, func(a, b scanner.HostView) int {
			return cmp.Or(primary(cmp.Compare(a.PortCount, b.PortCount)),
				cmp.Compare(b.CheckedAt, a.CheckedAt), address(a, b))
		})
	case "reasons":
		// Counted once per host: inside the comparator this would re-walk every signal list on
		// every comparison.
		badges := make(map[string]int, len(hosts))
		for _, host := range hosts {
			badges[host.IP] = sourceCount(host.Signals)
		}
		slices.SortStableFunc(hosts, func(a, b scanner.HostView) int {
			return cmp.Or(primary(cmp.Compare(badges[a.IP], badges[b.IP])),
				cmp.Compare(b.CheckedAt, a.CheckedAt), address(a, b))
		})
	case "band":
		slices.SortStableFunc(hosts, func(a, b scanner.HostView) int {
			return cmp.Or(primary(cmp.Compare(bandRank(a.Band), bandRank(b.Band))),
				cmp.Compare(b.CheckedAt, a.CheckedAt), address(a, b))
		})
	case "recent":
		slices.SortStableFunc(hosts, func(a, b scanner.HostView) int {
			return cmp.Or(primary(cmp.Compare(a.CheckedAt, b.CheckedAt)), address(a, b))
		})
	default:
		// No explicit sort is the existing newest-first order, regardless of a stray prefix.
		slices.SortStableFunc(hosts, func(a, b scanner.HostView) int {
			return cmp.Or(cmp.Compare(b.CheckedAt, a.CheckedAt), address(a, b))
		})
	}
}

// portRank decides which ports survive the maxPortsShown cut: the one filtered on, then the ones
// something fired on, then everything else. wanted is 0 when no port filter is set.
func portRank(p scanner.PortView, wanted int) int {
	switch {
	case wanted != 0 && p.Port == wanted:
		return 0
	case len(p.Signals) > 0:
		return 1
	}
	return 2
}

// bandRank puts the hosts worth looking at first, and the ones already dealt with last.
func bandRank(band string) int {
	switch band {
	case "high":
		return 0
	case "low":
		return 1
	case "ack":
		return 3
	}
	return 2
}
