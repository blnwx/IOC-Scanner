export const VIEWS = ["hosts", "domains", "analytics", "jarm", "jarm-blacklist", "log", "settings", "targets"] as const;
export type View = (typeof VIEWS)[number];

// Every filter lives in the URL, so each control's vocabulary is stated once here and read by both
// the control that renders it and the request builder in api.ts. A hand-typed URL should paint the
// page with the default rather than a broken control, which is what allowed does.
export function allowed(value: string | null, options: readonly string[], fallback = ""): string {
	return value && options.includes(value) ? value : fallback;
}

export const DEFAULT_BANDS: readonly string[] = ["high", "low", "clean"];
export const BANDS = ["high", "low", "clean", "ack"];

// An empty band list is a real selection — show nothing — so it has to survive the round trip. The
// absence of the parameter, not its emptiness, is what means "the default three".
export function selectedBands(params: URLSearchParams): readonly string[] {
	return params.has("band") ? params.getAll("band") : DEFAULT_BANDS;
}

export const ORIGINS = ["manual", "scheduled"];
export const LOG_LEVELS = ["ALERT", "ERROR", "WARN", "INFO", "DEBUG"];
export const PAGE_SIZES = ["25", "50", "100", "200"];
export const DEFAULT_SIZE = "50";

// The periods the analytics page offers, matching analyticsPeriods in src/analytics.go.
export const PERIODS: [string, string][] = [
	["latest", "Most recent full scan"],
	["1d", "Last 1 day"],
	["7d", "Last 7 days"],
	["30d", "Last 30 days"],
	["90d", "Last 90 days"],
	["all", "Everything stored"],
];
export const PERIOD_VALUES = PERIODS.map(([value]) => value);
export const DEFAULT_PERIOD = "30d";

// Each table's sortable columns: the sort values the Go handlers accept, ascending, with a "-"
// prefix asking for the reverse — see sortHosts in src/web.go, domains in src/domains.go and
// loadJARMRows in src/db.go.
export const HOST_SORTS = ["ip", "ports", "band", "reasons", "recent"];
// The feed-only table has no ports column, so it does not offer that ordering. Sorting by a
// column that is not on screen is what a sort carried over from the complete table would do.
export const FEED_ONLY_HOST_SORTS = HOST_SORTS.filter((sort) => sort !== "ports");
export const DOMAIN_SORTS = ["ip", "port", "name", "recent"];
export const JARM_SORTS = ["hash", "hosts", "first", "recent"];

export interface Indicator {
	source: string;
	value: string;
	tag: string;
	first_seen?: string;
	link?: string;
	confidence_level?: number;
}

export interface Port {
	ip: string;
	port: number;
	scanned_at: number;
	manual: boolean;
	subject: string;
	issuer: string;
	dns_names: string;
	not_before: number;
	not_after: number;
	signature_algorithm: string;
	serial_number: string;
	self_signed: boolean;
	fingerprint: string;
	jarm: string;
	signals: Indicator[] | null;
	band: string;
}

export interface Host {
	ip: string;
	ports: Port[];
	port_count: number;
	signals: Indicator[];
	band: string;
	checked_at: number;
	manual: boolean;
	live_tls: boolean;
}

export interface HostsResponse {
	in_scope: number;
	scanned: number;
	live_tls: number;
	high: number;
	low: number;
	acked: number;
	matched: number;
	page: number;
	pages: number;
	hosts: Host[];
	configured: boolean;
}

export interface Latency {
	successes: number;
	failures: number;
	timeouts: number;
	median_us: number;
	p90_us: number;
	average_us: number;
	min_us: number;
	max_us: number;
	q1_us: number;
	q3_us: number;
	budget_ms: number;
	budget_changed: boolean;
}

// One port's tally, in the coverage table and the TLS rankings alike. configured is only sent for
// the coverage rows: the rankings do not ask whether common_ports sweeps the port.
export interface PortCount {
	port: number;
	hosts: number;
	high: number;
	low: number;
	configured?: boolean;
}

export interface ScanTimeoutAnalytics {
	started_at: number;
	source: string;
	elapsed_ms: number;
	targets: number;
	max_workers: number;
	dial: Latency;
	tls: Latency;
	jarm: Latency;
	complete: Latency;
}

export interface AnalyticsResponse {
	period: string;
	generated_at: number;
	cost: { passes: number; targets: number };
	dial: Latency;
	tls: Latency;
	jarm: Latency;
	complete: Latency;
	coverage: { ports: PortCount[]; flagged: number; flagged_covered: number };
	feeds: {
		source: string;
		indicators: number;
		hosts: number;
		exclusive: number;
		local: boolean;
	}[];
	profile: {
		tls_high: PortCount[];
		tls_low: PortCount[];
		tls_flagged: PortCount[];
	};
	comparison?: { latest: ScanTimeoutAnalytics; previous: ScanTimeoutAnalytics };
}

export interface DomainRow {
	ip: string;
	port: number;
	scanned_at: number;
	names: string[];
}

export interface JarmRow {
	hash: string;
	hosts: number;
	first_seen: number;
	last_seen: number;
	blacklisted: boolean;
}

export interface JarmBlacklistEntry {
	label: string;
	hash: string;
}

export interface LogEntry {
	at: number;
	level: string;
	msg: string;
	attrs: string;
}

export interface Config {
	config: {
		refresh_seconds: number;
		retain_days: number;
	};
	feeds: { domain_ignorelist: string[] };
	scan: {
		allow: string[];
		deny: string[];
		targets_file: string;
		feed_only_targets_file: string;
		asn_refresh_minutes: number;
		common_ports: number[];
		scans_per_day: number;
		max_workers: number;
		dial_timeout_ms: number;
		tls_timeout_ms: number;
		jarm_timeout_ms: number;
	};
}

export interface SettingsResponse {
	config: Config;
	threatfox_auth_key_set: boolean;
}

export interface TargetRow {
	value: string;
	addresses: number;
	covered_by: string;
	expansion: PrefixRow[];
	status: string;
}

export interface PrefixRow {
	value: string;
	addresses: number;
	status: string;
}

export interface TargetsResponse {
	targets: TargetRow[];
	scannable: number;
	targets_file: string;
}

export interface ScanPass {
	running: boolean;
	queued: boolean;
	kind: string;
	target_count: number;
	progress: number;
	started_at: number;
	finished_at: number;
}

export interface ScanStatus {
	scheduled: ScanPass;
	manual: ScanPass;
}
