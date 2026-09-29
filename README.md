# IOC Scanner

Scans **your own** IP space for malicious-infrastructure indicators. Command and control, plus
other threat types (payload delivery, phishing, malware distribution). Two signals:

- **Feed hits**. An address of yours appears in a public threat feed.
- **Certificate hits**. A TLS certificate served by one of your hosts has a SHA-1 fingerprint
  SSLBL lists as botnet C2 or a CN/SAN domain listed by one of the domain-capable feeds.

It runs as a long-lived process. It re-pulls the feeds, sweeps the configured ports, and alerts
on stderr while writing everything to SQLite. An allowlist guardrail means it refuses to touch
address space you have not declared as yours.

IPv4 only. Scope lists may also name an ASN such as `AS13335`; RIPEstat supplies its announced
IPv4 prefixes.

## Requirements

- Go 1.26
- Node.js 20.19+ and npm (the Make targets build the embedded React dashboard)
- `ulimit -n` above `max_workers`. One worker-limited sweep runs at a time. The process warns at startup if the limit is
  too low. Past the limit, dials fail with `EMFILE`: those ports are counted as untested rather
  than closed, and each one logs a warning naming the errno. Only the errnos that mean this
  machine ran out of something (`EMFILE`, `ENFILE`, `EADDRNOTAVAIL`, `ENOBUFS`, `ENOMEM`,
  `EAGAIN`) count as untested. A refusal, reset or unreachable route is a real answer about the
  port, and is recorded as closed.

## Build

```sh
make build    # produces ./iocscanner
make lint     # lints the React/TypeScript source
make test     # builds, lints, then runs the frontend and Go suites
make run      # build, then run
```

Go sources live in `src/`; the React dashboard source lives in `frontend/`. Generated dashboard
assets are embedded from `src/web/` and are built by Make rather than committed. `go.mod` stays at
the repo root. Run everything from the repo root.
The binary resolves `config.toml`, the targets file, `db/asn_prefixes.json` and `db/matches.db` relative to the working
directory. Every indicator comes from the feeds; the scanner ships no local pattern list.

## Configure

```sh
cp config.example.toml config.toml
cp scan_targets.example.json scan_targets.json
```

**Every key shown in the example is required. There are no defaults.** An omitted key decodes to zero, and zero is a
startup error, so a missing line can never be mistaken for a working one. Unknown keys are
rejected too, so a typo fails loudly. Two exceptions: `scan.deny` (empty denies nothing) and
`feeds.threatfox_auth_key` (empty skips that one feed).

`config.toml` holds an API key once set. Keep it out of git, it is already in `.gitignore`.

| Key | What it does |
| --- | --- |
| `config.refresh_seconds` | How often the config and targets files are re-read. Edits to the allow/deny lists apply without a restart. |
| `feeds.threatfox_auth_key` | abuse.ch ThreatFox API key. Empty skips the ThreatFox feed. |
| `scan.allow` | IPs, CIDRs and ASNs you are authorized to scan. Cannot be empty. |
| `scan.deny` | IPs, CIDRs and ASNs to exclude from the allowlist, e.g. a gateway. |
| `scan.targets_file` | Path to the JSON array of IP, CIDR or ASN targets. These are the addresses checked and scanned. |
| `scan.feed_only_targets_file` | Optional path to a JSON array in the same format. These addresses receive direct IP/IP:port feed matching only and are never probed. Missing or blank disables the feature; Settings creates a newly configured file as `[]`. It cannot be the same path as `targets_file`. |
| `scan.asn_refresh_minutes` | How often ASN entries are resolved through RIPEstat. Required; minimum 15 minutes. The last good prefixes are cached across restarts. If a refresh leaves no authorized targets, scheduled scanning pauses from the next pass until a later refresh restores them; a pass already running finishes on the scope it started with. |
| `scan.scans_per_day` | 1-24. Sets the full-scan interval (`24h / scans_per_day`), timed from the start of a pass. |
| `scan.common_ports` | Ports tried first, in this order, in every full scan. The dashboard can also scan only these ports. |
| `scan.max_workers` | Dials in flight at once. A full sweep is 65535 dials per target, so this is what decides hours versus months. |
| `scan.dial_timeout_ms` | How long a port has to answer before it counts as filtered. A closed port refuses instantly, so only filtered ports pay this. That is what a sweep costs. |
| `scan.tls_timeout_ms` | Budget for the TLS handshake, timed from the moment the port answered. Separate from the dial budget because only open ports reach a handshake, and they are rare. A generous value here collects certificates from slow hosts without slowing the sweep. |
| `scan.jarm_timeout_ms` | Budget for **one** JARM probe. A fingerprint is ten probes run back to back, so a silent host costs ten times this before the sweep moves on. Keep it well under `tls_timeout_ms`. |

The targets file is a JSON array of IPs, CIDRs and ASNs:

```json
["192.168.0.2", "192.0.2.2/31", "AS13335"]
```

## Safety

An address is scanned only if it is in `targets` **and** in `allow` **and** not in `deny`.
Feed-only targets use the same allow/deny guardrail. The dashboard refuses to save a feed-only
list where every entry is denied, out of scope, or already an active target, rather than storing
one that can never match; a file already on disk is loaded as it is, so a reload is never blocked.
Active targets win when the files overlap, and the Targets page marks a feed-only entry the sweep
already covers as "actively scanned". Saving either target list re-checks the cached feed
indicators immediately, so a new feed-only address shows its hits on the next dashboard poll
rather than at the next 15-minute feed refresh; there is no probe that would otherwise fill it in. Which side a stored hit belongs to is decided by the running scope, so moving
an address between the two files moves its whole host with it on the next dashboard poll. Removing
an unscanned address from both hides its retained hit until the address is targeted or scanned.
The process refuses to start if none of the targets overlaps the allowlist ("all targets are
out of scope"). If the config or targets file fails to parse on reload, the last good scope
is kept rather than blanked, so a half-saved edit cannot widen or empty your scope.

## Run

```sh
./iocscanner                          # uses ./config.toml
./iocscanner -config /path/to.toml
./iocscanner -v                       # include alert logs
./iocscanner -vv                      # include debug details and every open port
./iocscanner -output report.json      # JSON report to a file instead of stdout
./iocscanner -scan 192.0.2.5          # scan one IP, CIDR or ASN once, then exit
./iocscanner -scan 192.0.2.5 -feed-only  # match it against the feeds, probe nothing
./iocscanner -listen 127.0.0.1:8080   # also serve the dashboard
```

`-v` adds alerts; `-vv` (or `-v -v`) adds debug details.
By default, INFO, warnings and errors
print to the terminal. With `-output`, findings are omitted from terminal logs at every verbosity;
they remain in the report and dashboard. The dashboard retains INFO and above regardless of
terminal verbosity, and includes DEBUG at debug verbosity. Ctrl-C (or `SIGTERM`) shuts down
gracefully. In-flight dials fail immediately and results already found are still written.

`-scan` is the on-demand mode. The target on the command line is the whole scope and
both configured target files are ignored. `allow`/`deny` still apply, and an out-of-scope argument exits
non-zero before anything is dialled. It refreshes the feeds once, sweeps all ports in one pass
with the common ports first, writes the report, and exits. A `scan complete` line gives the
targets scanned and the number of flagged hosts. No reload loop, no repeat pass.

`-feed-only` cuts that down to the feed check. The target goes on the side the sweep never probes:
the run refreshes the feeds, records any hit naming the address, writes the report and exits
without opening a single connection to it. `allow`/`deny` still apply. The flag needs `-scan` —
a scheduled run takes its feed-only list from `scan.feed_only_targets_file`, which the dashboard
can edit without a restart.

## Dashboard

`-listen` serves a web view of the same data the report is built from, and edits the scanner's own
configuration. Without the flag no socket is opened. `-scan` ignores it: that mode exits before a
server would be useful.

> **It has no authentication and no TLS.** Bind it to loopback. Anything else publishes your
> scan results and your scope to whoever can reach the port — and hands over the settings that
> decide where the scanner points.

Every endpoint that changes something requires `Content-Type: application/json`. A cross-origin
form cannot set that header, and a cross-origin script must pass a browser preflight. The server
does not check the `Host` header, so this does not protect against DNS rebinding. Treat the
dashboard as trusted-local-only.

The Hosts view lists every stored host with an open port or feed match, including manual results
outside the current scope, most recently observed first. Scanning a feed-only address by hand moves
it here, since it now has ports and a certificate to show; an earlier sweep of an address since
retired to the feed-only list does not, so retiring one moves it off this view and keeps it off.
Each row shows whether its newest scan was manual or scheduled, plus its open ports (flagged ones
coloured), band, and reasons. Clicking a host opens the full certificate record per port: subject,
issuer, SANs, validity, signature algorithm, serial, SHA-1 and JARM fingerprints, and which check
fired on it. The search box matches on address, port, reason, tag, SHA-1 and JARM fingerprints,
serial, subject, issuer, SANs, signature algorithm and `self-signed`, all at once. Validity dates
are not searchable — sort or read them off the record. Filters cover band, scan origin, a specific
open port, sort order and page size. Scan origin shows all manual and scheduled results by default.
The band filter is a set of checkboxes: what is ticked is what the table shows.

Every row ends with an **ACK** button — mark that host as dealt with, whether that means the
server was destroyed, the content was pulled, or you read it and it was clean. It is one click
from the list, and the column is pinned to the right edge so a host answering on a dozen ports
cannot push it out of reach. An acknowledged host shows `ACK` in place of its band, drops out of
the High and Low tallies into its own, and is hidden from the table until you tick
**Acknowledged** in the band filter. The button then reads **RESET** and puts it back.
Tick individual rows to apply **ACK SELECTED** or **RESET SELECTED** to only those hosts. The
table-header checkbox selects all visible rows compatible with the current ACK selection.

The acknowledgement is recorded against the host's observed state and holds only while nothing
changes. Any change to its ports, certificate or JARM details, or signals retires the ACK and puts
the host back in the queue, whether the new state is clean or dirty.

The **Analytics** view answers two questions the host table cannot. **Performance**: how long each
stage of a probe actually takes, so `dial_timeout_ms`, `tls_timeout_ms` and `jarm_timeout_ms` are
set against measurements rather than guesses. One card per stage gives its exact median and 90th
percentile over successful attempts beside the count that reached the configured deadline; a
refusal or a peer that does not speak TLS is counted separately, because neither says the limit is
too low. The spread panel puts the dial, the handshake, one JARM probe and a complete probe —
dial, handshake and all ten probes on a port that finished every stage — on one page, each row
scaled to its own range. **C2 characteristics**: the ports your HIGH
findings sit on, what share of the rated endpoints a full scan finds the configured `scan.common_ports`
would have caught — with a row for every busy port it misses and every configured port that finds
nothing — what each feed returns for what it lists, and the issuers, signature algorithms and ports
of the certificates actually collected.

The period control picks the window. The page does not poll — it reads a history that moves once a
sweep — so it prints the time it was generated and leaves it at that. A reload or a period change
refetches. The Timeouts section can switch from those period totals to the latest two completed
full scans, regardless of their origin or the selected period. It shows the same outcomes and timing
distribution with neutral deltas, plus a warning when origin, target count, or worker count changed.
It does not claim a config change caused an improvement: changing a timeout also changes which
outcome a port lands in, and network conditions can change between scans. Use **REFRESH** after a
new full scan finishes to fetch the new pair.

The **Domains** view is the inventory of names the scan has actually collected: one row per
endpoint, with the host address, the port, and every domain that certificate carried. The names
come from the certificate's common name first, then its SANs, deduplicated into one cell — some
C2 certificates put the domain only in the common name, which is why both are read. Each name is a
VirusTotal lookup, a wildcard resolving to the domain it covers; the address copies on click.

Subjects that are not shaped like a domain are dropped rather than listed, so a self-signed
certificate naming `198.51.100.7`, `localhost`, or a machine like `WIN-DESKTOP` contributes
nothing and an endpoint left with no usable name never appears. Wildcards are kept as they are.
Search matches the address, the port and every name at once. Rows are newest first, and the headers
also sort by address, port or first domain. Like the host table, it includes everything ever seen,
which is what the **From** and **To** filters narrow: they bound the scan time by whole days, either
end usable alone, and **TODAY** sets both to the current one. Every timestamp on the dashboard is
UTC, and the columns say so, because these rows are read beside feeds and lookups quoted that way —
so a day runs midnight to midnight UTC, and a filter URL selects the same span for whoever opens it.

The **JARM** view lists hashes by lifetime host count, rarest first, with their first and last
sighting. Its search matches hashes. Use **BLACKLIST** on a sighting to give it a label and add it
to the local blacklist.

The **JARM Blacklist** view is the operator-curated list, independent of sightings. Add one or more
`Label,Hash` lines or remove an existing row. A matching probe is High immediately; adding,
relabelling, or removing a hash also re-evaluates stored scans, acknowledgements, and the current
report without waiting for another sweep.

The **Log** view shows what the process has logged since it started — alerts, errors, warnings
and info — filterable by level. It is held in memory, capped at 500 entries, and is **empty
after a restart**. Nothing survives one unless you capture stderr yourself — redirect it to a
file, or let the supervisor running the scanner collect it.

The **Settings** view edits `config.toml` itself: every setting except the ThreatFox key, which
this server never handles — it only reports whether one is set. A save replaces the whole file
and the scanner runs the new settings immediately, without a restart. It is checked before
anything is written, so a refused save names the setting it refused and leaves the file untouched.
That includes the allowlist: an edit that would leave no target in scope is refused rather than
stranding the scanner.

> Saving rewrites `config.toml` **without its comments** — the encoder emits values only.
> `config.example.toml` is the documented copy.

The **Targets** view adds and removes scan targets, writing the file named by `scan.targets_file`.
Each row carries what the scanner would actually do with it — `in scope`, `partially in scope`,
`denied`, or `out of scope` — because the allow and deny lists narrow the targets file, and a target
that is listed but never probed is otherwise invisible until a sweep covers nothing. A row you have
added
but not saved reads `unsaved`, so the table doubles as the diff. Entries are written back
normalised: masked, deduplicated, and a bare address as a `/32`, which is what is swept.

Enter a comma-separated list of IPs or CIDRs in **Targets**, above **Scan common ports** and
**Scan all ports**, to scan only those addresses. The field is **required** — sweeping the saved
targets is what the schedule already does, so the only thing this adds is pointing the scanner
somewhere it does not — and the buttons stay dark until something is typed into it. The list is
temporary and does not change the Targets page; every address must be inside `scan.allow` and
outside `scan.deny`, or the whole request is refused. The scan runs **alongside** the sweep already
in flight rather than stopping it, on its own loop, so the scheduled interval is untouched. Both
passes size their own worker semaphore, so while they overlap the dials in flight peak at twice
`max_workers` — raise `ulimit -n` accordingly, or the extra dials fail and ports go untested. The buttons
stay available *during* a scheduled sweep, which is exactly when an extra scan is worth asking for;
they go dark only while your own sweep is running.

Above them are separate scheduled and manual scan indicators, on screen from every view. Each dot
fills and beats while its scan is running, with the target and port coverage plus elapsed time, and
shows when that scan last ended while idle. A newly requested manual scan polls every second until
it starts; running and idle indicators follow the same ten-second poll as the tables.

The views poll every ten seconds, pausing while the tab is hidden or a record is open. Settings,
Targets, and JARM Blacklist are never polled — a refresh would overwrite a half-typed form — so
they load once and again after a save.

JSON endpoints back the page, if you would rather script against them:

```sh
curl -s localhost:8080/api/hosts | jq '{scanned, high, low, acked}'
curl -s localhost:8080/api/hosts/feed-only | jq '{scanned, high, low, acked}'
curl -s 'localhost:8080/api/hosts?q=8443&band=high&band=low&origin=manual&sort=ip&page=1&size=50'
curl -s 'localhost:8080/api/hosts?sort=-ports'  # a "-" on the sort key reverses it
curl -s 'localhost:8080/api/jarm?q=27d40d'
curl -s localhost:8080/api/jarm-blacklist
curl -s 'localhost:8080/api/logs?level=ERROR'
curl -s localhost:8080/api/scan      # what is sweeping now
curl -s localhost:8080/api/settings  # the running config, never the auth key
curl -s localhost:8080/api/targets   # each target with its verdict against allow and deny
curl -s 'localhost:8080/api/targets?target=feed-only'

# Toggle the acknowledgement on any stored host.
curl -s -X POST localhost:8080/api/ack -H 'Content-Type: application/json' -d '{"ip":"192.0.2.50"}'

# Upsert labeled JARM hashes, or remove one. POST is a bare array and is rejected atomically.
curl -s -X POST localhost:8080/api/jarm-blacklist -H 'Content-Type: application/json' \
  -d '[{"label":"CobaltStrike","hash":"27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"}]'
curl -s -X DELETE localhost:8080/api/jarm-blacklist -H 'Content-Type: application/json' \
  -d '{"hash":"27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"}'

# Set acknowledgement explicitly for up to 200 hosts (the dashboard uses this for bulk actions).
curl -s -X POST localhost:8080/api/ack -H 'Content-Type: application/json' \
  -d '{"ips":["192.0.2.50","192.0.2.51"],"acked":true}'

# Scan a temporary list without changing the saved targets, alongside the sweep in flight. targets
# is required: 400 without it, 403 outside allow or inside deny, 409 when a scan of yours is
# already queued or running, 202 when it is taken.
curl -s -X POST localhost:8080/api/scan -H 'Content-Type: application/json' \
  -d '{"kind":"full","targets":"192.0.2.5, 198.51.100.0/28"}'

# Replace the config, or the targets. Both are whole replacements, not patches.
curl -s localhost:8080/api/settings | jq .config > settings.json
curl -s -X PUT localhost:8080/api/settings -H 'Content-Type: application/json' -d @settings.json
curl -s -X PUT localhost:8080/api/targets -H 'Content-Type: application/json' \
  -d '{"targets":["192.0.2.0/24","198.51.100.7"]}'
```

`band` repeats once per value and is a whitelist: `band=high&band=low` shows those two, and no
`band` parameter at all means no filter. `origin=manual` or `origin=scheduled` filters by the
newest result shown for each host; leaving it out shows both. `page` and `size` are clamped rather than rejected —
`size` caps at 200, and a page past the end returns the last one. The
`scanned`/`high`/`low`/`acked` tallies always cover everything stored, not the filtered page, so a
search never moves them. `scanned` retains its API name but counts all observed hosts, including
feed-only matches.

Every endpoint that writes insists on the JSON content type. A cross-origin form cannot set it,
and a cross-origin script must pass a browser preflight. The server does not validate the `Host`
header, so these checks do not stop DNS rebinding. `POST /api/ack` refuses any host with no scan or
feed-match rows; it does not apply the current scope because manual results remain actionable.

`PUT /api/settings` and `PUT /api/targets` replace the whole thing: a missing setting is an error,
not a default, and an unknown field is an error rather than a silently dropped one. Read the
current values first and send them back edited. Both validate fully before writing, so a rejected
request leaves the file byte-for-byte as it was.

A host carries at most 50 port records, so one tarpit answering on every port cannot fill the
response; `port_count` still gives the real number. The port you filtered on and any port
something fired on are kept ahead of the rest, so the reason a host matched always survives
the cut.

## Output

With `-v`, terminal logs look like this (ALERT lines appear only without `-output`):

```
INFO   starting  targets=512 scannable=510 allow=256 deny=1
INFO   refreshing feeds
INFO   feeds refreshed  feeds=11/11 indicators=13061 matches=1
ALERT  feed match  ip=192.0.2.2 feed_only=false band=high source=feodo tag=QakBot indicator=192.0.2.2:8443 first_seen=2025-06-14T08:22:00Z
INFO   sweep started  kind=full targets=510 ports=33422850
ALERT  suspicious host  target=192.0.2.3:443 band=high reasons="sslbl_cert (PureLogsStealer C&C) first seen 2025-06-14T08:22:00Z" subject=localhost issuer=localhost expires="2019-04-12 (expired)" sigalg=SHA256-RSA sha1=283042355c89f2c59e260246d1488a73a8bef7b2
INFO   sweep complete  kind=full hosts=510 open_ports=3 live_tls_hosts=2 high=1 low=0 took=18h2m41.203s
INFO   report updated  live_tls_hosts=2 high=1 low=0 path=report.json
```

The two summary lines answer different questions. `sweep complete` counts what that pass found.
`report updated` carries the report's cumulative tally over every scan stored so far, and always
agrees with the JSON below. A malformed feed row is skipped with one aggregated warning while valid
rows replace that feed's snapshot; an unreadable or all-invalid response logs an error and retains
the last-good snapshot. Feed health is reported by `feeds refreshed`, which is the loop that
owns it.

Empty fields are dropped rather than printed blank. An open port with no certificate shows no
`subject=`/`sha1=`, and one that answered no JARM probe shows no `jarm=`.

`jarm=` is the JARM fingerprint of the server's TLS stack — its implementation and configuration
rather than its certificate, so it survives the certificate rotation that defeats a fingerprint
feed. Only ports that complete a TLS handshake are fingerprinted — a port that failed the
handshake does not speak TLS, and ten more dials would only confirm it.

`first_seen` is the feed's own timestamp for the record that fired, normalised to RFC3339 UTC.
For URLHaus it is the last-online date; for the ThreatView Cobalt Strike feed it is the detection
date. The dashboard and alerts label those two timestamps accordingly. A feed that omits a date,
or a local certificate check, prints nothing.

At the end of every sweep pass a JSON report of the flagged hosts is written to `-output`, or
to stdout when the flag is absent. Logs go to stderr, so the two never mix. The file is written
whole and renamed into place, so a reader never catches it half-written. With nothing flagged the
file still gets `[]`, but stdout stays empty rather than printing a bare `[]` once per sweep — the
`report updated` line already carries the tally.

```json
[
  {
    "ip": "192.0.2.3",
    "open_tls_ports": [443],
    "signals": [{"source": "sslbl_cert", "value": "283042355c89…", "tag": "PureLogsStealer C&C",
                 "first_seen": "2025-06-14T08:22:00Z"}],
    "band": "high",
    "checked_at": "2025-07-31T16:15:02Z"
  }
]
```

Everything lands in `db/matches.db` (SQLite, WAL):

- **`matches`** holds feed hits on your addresses: `ip`, `source`, `value`, `tag`, `first_seen`
  (the feed's own stamp for the record), `seen_at` (when this scanner last confirmed it).
- **`scans`** holds every open port found, with the certificate fields when the port spoke TLS:
  `ip`, `port`, `scanned_at`, `subject`, `issuer`, `dns_names`, `not_after`,
  `signature_algorithm`, `fingerprint`, `jarm`.
- **`jarm_sightings`** holds one lifetime row per `(hash, ip, port)`, with `first_seen` and
  `last_seen`.
- **`jarm_blacklist`** holds the local `hash` → `label` list. It is loaded into its own
  thread-safe lookup at startup and is not part of the remote feed cache or sightings table.

```sh
sqlite3 db/matches.db "SELECT ip, port, subject, fingerprint FROM scans WHERE fingerprint != ''"

# Lifetime view of every observed endpoint.
sqlite3 db/matches.db "SELECT hash, COUNT(DISTINCT ip) AS hosts FROM jarm_sightings
  GROUP BY hash ORDER BY hosts ASC"
```

## Feeds

| Feed | Contributes | Key needed |
| --- | --- | --- |
| ThreatFox (abuse.ch) | `ip:port` IOCs of every threat type, last 7 days | Yes, skipped if unset |
| Feodo Tracker | Botnet C2 IP blocklist | No |
| SSLBL IP blocklist | Botnet C2 IPs | No |
| SSLBL certificate blocklist | SHA-1 fingerprints of C2 certificates | No |
| TweetFeed.live | Addresses, domains, and URL hosts posted on Twitter/X, last 7 days | No |
| Phishing Army | Phishing domains matched against certificate CNs and SANs by registrable domain | No |
| URLHaus recent | Online malware URL hosts, with threat, tags, last-online date, and record link | No |
| C2IntelFeeds | Cobalt Strike domain/IP mappings and IOC descriptions | No |
| ThreatView | Cobalt Strike IP/domain mappings plus high-confidence domain and URL feeds | No |

Feeds are re-pulled every 15 minutes. A feed that fails keeps its last good result, so a
transient outage does not blank the list.

An indicator is matched at whichever point in a scan the thing it names is known:

| Known | Matched against |
| --- | --- |
| The target address, before anything is probed | Feed entries naming that address, with or without a port |
| The certificate, once the TLS handshake completes | Feed entries naming its SHA-1, its SANs, or its common name, including domains extracted from URLs. Phishing Army, URLHaus, C2IntelFeeds, and ThreatView compare registrable domains; TweetFeed remains exact. A wildcard SAN matches on the domain it covers |
| The JARM hash, once the ten probes are done | The local JARM blacklist, plus any feed entry naming that hash |

TweetFeed is the one crowd-sourced list here: anyone can post an indicator to it. Its hits still
alert at `high` — a feed naming your address is evidence, not a heuristic — but the dashboard
badges it apart from the curated lists so a lone TweetFeed hit is never mistaken for an abuse.ch
one. Entries with no hashtags are tagged with the handle that posted them.

