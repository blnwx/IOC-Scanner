import type { Host, Indicator } from "./types";

// Where a source's signal comes from. "curated" feeds name the address or certificate directly
// and rate HIGH. "crowd" is lower-trust crowdsourced feeds. "local" is the heuristic checks that
// only rate a host LOW on their own (the signals marked Soft in src/scan.go). Every source the backend can
// emit must be listed here — a new feed source needs an entry added.
export const SOURCE_TIERS: Record<string, string> = {
	threatfox: "curated",
	feodo: "curated",
	sslbl: "curated",
	sslbl_cert: "curated",
	phishing_army: "curated",
	urlhaus: "curated",
	c2intel: "curated",
	threatview: "curated",
	jarm_blacklist: "curated",
	tweetfeed: "crowd",
	self_signed: "local",
	cert_validity: "local",
	expired_cert: "local",
	long_validity: "local",
};

const TIER_RANK: Record<string, number> = { curated: 0, crowd: 1, local: 2 };

// Falls back to "curated" only as a safety net for a source the backend added without an entry
// above — SOURCE_TIERS should always be kept explicit and complete.
export function tierOf(source: string): string {
	return SOURCE_TIERS[source] || "curated";
}

// Sorts signal sources curated -> crowd -> local, so the reason column's ellipsis truncation
// (which cuts off whatever doesn't fit) drops the least trustworthy badges first.
export function sortSourcesByBand(sources: string[]): string[] {
	return [...sources].sort((a, b) => TIER_RANK[tierOf(a)] - TIER_RANK[tierOf(b)]);
}

export function detailLink(signal: Indicator, ip: string) {
	return signal.source === "feodo"
		? `https://feodotracker.abuse.ch/browse/host/${ip}/`
		: ["threatfox", "tweetfeed", "urlhaus"].includes(signal.source)
			? signal.link || ""
			: "";
}

// Mirrors certName in src/domains.go: a certificate subject is only worth a lookup when it is
// actually a hostname — a CA's own name or an internal label has no record to open.
const DOMAIN_NAME = /^(\*\.)?([a-z0-9_-]+\.)+([a-z]{2,}|xn--[a-z0-9-]+)$/;

// Third-party record for a name the scanner read off a certificate. The feeds name a domain and
// little else, so this is usually the only route to any detail behind a hit.
export function virusTotalDomain(raw: string) {
	const name = raw
		.trim()
		.toLowerCase()
		.replace(/^\.+|\.+$/g, "");
	if (!DOMAIN_NAME.test(name)) return "";
	return `https://www.virustotal.com/gui/domain/${encodeURIComponent(name.replace(/^\*\./, ""))}`;
}

export function virusTotalAddress(ip: string) {
	return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
}

export function feedDate(signal: Indicator) {
	if (!signal.first_seen) return "";
	const label = signal.source === "urlhaus" ? "last online" : signal.source === "threatview" ? "detected" : "first seen";
	return `  ${label} ${signal.first_seen}`;
}

export function reasonText(signal: Indicator) {
	return `${signal.source} — ${signal.tag}`;
}

export function sourceLinks(host: Host, source: string): string[] {
	if (source === "feodo") return [`https://feodotracker.abuse.ch/browse/host/${host.ip}/`];
	if (source === "threatfox") return [`https://threatfox.abuse.ch/browse.php?search=ioc%3A${host.ip}`];
	if (["tweetfeed", "urlhaus"].includes(source)) return host.signals.filter((signal) => signal.source === source).map((signal) => signal.link || "");
	return [];
}
