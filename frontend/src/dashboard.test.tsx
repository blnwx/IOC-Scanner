import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter, useLocation, useNavigate } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// The stylesheets are loaded (vite.config.ts sets test.css) so the layout and typography rules the
// tables and the toolbar depend on can be asserted rather than assumed.
import "./analytics.css";
import "./app.css";
import "./table.css";
import App from "./App";
import { Badge } from "./components/Badge";
import { HostDetail } from "./components/HostDetail";
import { HostRow } from "./components/HostRow";
import { ScanControls } from "./components/ScanControls";
import { SettingsForm } from "./components/SettingsForm";
import { SignalReason } from "./components/SignalReason";
import { Table } from "./components/Table";
import { TargetEditor } from "./components/TargetEditor";
import { ScanProvider } from "./context/ScanContext";
import { resetResourceCache } from "./hooks/useResource";
import { sortSourcesByBand } from "./host-utils";
import { spreadLabels } from "./pages/Analytics";
import { Hosts } from "./pages/Hosts";
import { JarmBlacklist } from "./pages/JarmBlacklist";
import type { AnalyticsResponse, Config, DomainRow, Host, Port, ScanStatus, SettingsResponse } from "./types";
import { day, elapsed, parseEntries, parseTarget, stamp, utcDay } from "./utils";

const scan: ScanStatus = {
	scheduled: {
		running: false,
		queued: false,
		kind: "full",
		target_count: 1,
		progress: 0,
		started_at: 0,
		finished_at: 0,
	},
	manual: {
		running: false,
		queued: false,
		kind: "full",
		target_count: 0,
		progress: 0,
		started_at: 0,
		finished_at: 0,
	},
};

const config: Config = {
	config: { refresh_seconds: 60, retain_days: 30 },
	feeds: { domain_ignorelist: [] },
	scan: {
		targets_file: "scan_targets.json",
		feed_only_targets_file: "",
		asn_refresh_minutes: 60,
		scans_per_day: 1,
		max_workers: 100,
		dial_timeout_ms: 500,
		tls_timeout_ms: 1000,
		jarm_timeout_ms: 200,
		allow: ["192.0.2.0/24"],
		deny: [],
		common_ports: [443],
	},
};

const domains: DomainRow[] = [
	{
		ip: "192.0.2.9",
		port: 8443,
		scanned_at: 1_700_000_000,
		names: ["panel.badhost.net"],
	},
	{
		ip: "192.0.2.10",
		port: 443,
		scanned_at: 1_700_000_001,
		names: ["c2.example.com", "*.example.com"],
	},
];

const analytics: AnalyticsResponse = {
	period: "30d",
	generated_at: 1_700_000_000,
	cost: { passes: 14, targets: 254 },
	dial: {
		successes: 10,
		failures: 300,
		timeouts: 100,
		median_us: 4_000,
		p90_us: 9_000,
		average_us: 5_000,
		min_us: 500,
		max_us: 10_000,
		q1_us: 1_200,
		q3_us: 8_400,
		budget_ms: 500,
		budget_changed: false,
	},
	tls: {
		successes: 10,
		failures: 20,
		timeouts: 2,
		median_us: 50_000,
		p90_us: 900_000,
		average_us: 60_000,
		min_us: 10_000,
		max_us: 950_000,
		q1_us: 20_000,
		q3_us: 90_000,
		budget_ms: 1000,
		budget_changed: false,
	},
	jarm: {
		successes: 13,
		failures: 3,
		timeouts: 147,
		median_us: 25_000,
		p90_us: 1_500_000,
		average_us: 30_000,
		min_us: 5_000,
		max_us: 1_900_000,
		q1_us: 10_000,
		q3_us: 45_000,
		budget_ms: 2000,
		budget_changed: false,
	},
	complete: {
		successes: 8,
		failures: 0,
		timeouts: 0,
		median_us: 1_200_000,
		p90_us: 2_400_000,
		average_us: 1_300_000,
		min_us: 500_000,
		max_us: 2_800_000,
		q1_us: 900_000,
		q3_us: 1_800_000,
		budget_ms: 0,
		budget_changed: false,
	},
	coverage: {
		ports: [
			{ port: 4444, hosts: 4, high: 2, low: 1 },
			{ port: 443, hosts: 12, high: 1, low: 3, configured: true },
			{ port: 2222, hosts: 6, high: 1, low: 5 },
			...Array.from({ length: 10 }, (_, index) => ({
				port: 9001 + index,
				hosts: 1,
				high: 0,
				low: 1,
			})),
			{ port: 22, hosts: 100, high: 0, low: 0, configured: true },
			{ port: 8080, hosts: 0, high: 0, low: 0, configured: true },
			{ port: 9999, hosts: 20, high: 0, low: 0 },
		],
		flagged: 13,
		flagged_covered: 4,
	},
	feeds: [
		{
			source: "threatfox",
			indicators: 12431,
			hosts: 14,
			exclusive: 9,
			local: false,
		},
		{ source: "feodo", indicators: 250, hosts: 1, exclusive: 1, local: false },
		{
			source: "phishing_army",
			indicators: 42000,
			hosts: 0,
			exclusive: 0,
			local: false,
		},
		{
			source: "jarm_blacklist",
			indicators: 8,
			hosts: 2,
			exclusive: 0,
			local: true,
		},
	],
	profile: {
		tls_high: [{ port: 8443, hosts: 6, high: 5, low: 0 }],
		tls_low: [{ port: 443, hosts: 12, high: 4, low: 3 }],
		tls_flagged: [{ port: 443, hosts: 12, high: 4, low: 3 }],
	},
};

analytics.comparison = {
	previous: {
		started_at: 1_699_000_000,
		source: "scheduled",
		elapsed_ms: 20_000,
		targets: 200,
		max_workers: 50,
		dial: {
			...analytics.dial,
			successes: 8,
			failures: 320,
			timeouts: 120,
			median_us: 6_000,
			budget_ms: 750,
		},
		tls: {
			...analytics.tls,
			successes: 8,
			failures: 22,
			timeouts: 4,
			median_us: 70_000,
			budget_ms: 1500,
		},
		jarm: {
			...analytics.jarm,
			successes: 10,
			failures: 4,
			timeouts: 160,
			median_us: 30_000,
			budget_ms: 2500,
		},
		complete: { ...analytics.complete, successes: 6, median_us: 1_400_000 },
	},
	latest: {
		started_at: 1_700_000_000,
		source: "manual",
		elapsed_ms: 10_000,
		targets: 254,
		max_workers: 100,
		dial: { ...analytics.dial },
		tls: { ...analytics.tls },
		jarm: { ...analytics.jarm },
		complete: { ...analytics.complete },
	},
};

function json(body: unknown, status = 200) {
	return Promise.resolve(
		new Response(JSON.stringify(body), {
			status,
			headers: { "Content-Type": "application/json" },
		}),
	);
}

function hosts(ip: string) {
	return {
		configured: true,
		in_scope: 1,
		scanned: 1,
		live_tls: 1,
		high: 1,
		low: 0,
		acked: 0,
		matched: 1,
		page: 1,
		pages: 1,
		hosts: [
			{
				ip,
				ports: [],
				port_count: 0,
				signals: [{ source: "threatfox", value: ip, tag: "C2" }],
				band: "high",
				checked_at: 1,
				manual: false,
				live_tls: false,
			},
		],
	};
}

function LocationProbe() {
	const location = useLocation();
	const navigate = useNavigate();
	return (
		<>
			<output data-testid="location">
				{location.pathname}
				{location.search}
			</output>
			<button type="button" onClick={() => navigate(-1)}>
				History back
			</button>
			<button type="button" onClick={() => navigate(1)}>
				History forward
			</button>
		</>
	);
}

beforeEach(() => {
	resetResourceCache();
	const values = new Map<string, string>();
	Object.defineProperty(window, "localStorage", {
		configurable: true,
		value: {
			getItem: (key: string) => values.get(key) ?? null,
			setItem: (key: string, value: string) => values.set(key, value),
			removeItem: (key: string) => values.delete(key),
			clear: () => values.clear(),
		},
	});
});

afterEach(() => {
	cleanup();
	vi.useRealTimers();
	vi.restoreAllMocks();
});

it("names the domain matched by Phishing Army", () => {
	render(
		<SignalReason
			signal={{
				source: "phishing_army",
				value: "example.co.uk",
				tag: "phishing",
			}}
			ip="192.0.2.9"
		/>,
	);
	expect(screen.getByText("phishing — example.co.uk", { exact: false })).toBeTruthy();
});

it("labels feed-specific dates and links URLHaus records", () => {
	render(
		<SignalReason
			signal={{
				source: "urlhaus",
				value: "192.0.2.9",
				tag: "malware_download",
				first_seen: "2026-08-20T09:00:00Z",
				link: "https://urlhaus.abuse.ch/url/201/",
			}}
			ip="192.0.2.9"
		/>,
	);
	expect(screen.getByText(/last online 2026-08-20T09:00:00Z/)).toBeTruthy();
	expect(screen.getByRole("link", { name: "urlhaus" }).getAttribute("href")).toBe("https://urlhaus.abuse.ch/url/201/");
	expect(screen.queryByRole("link", { name: /on VirusTotal/ })).toBeNull();
});

const hostShape: Host = {
	ip: "192.0.2.9",
	ports: [],
	port_count: 0,
	signals: [],
	band: "high",
	checked_at: 1,
	manual: false,
	live_tls: false,
};

const portShape: Port = {
	ip: "192.0.2.9",
	port: 443,
	scanned_at: 1,
	manual: false,
	subject: "",
	issuer: "",
	dns_names: "",
	not_before: 0,
	not_after: 0,
	signature_algorithm: "",
	serial_number: "",
	self_signed: false,
	fingerprint: "",
	jarm: "",
	signals: null,
	band: "",
};

it("looks up the certificate subject and the host address from the expanded record", () => {
	render(
		<HostDetail
			host={{
				...hostShape,
				ip: "192.0.2.9",
				ports: [{ ...portShape, port: 443, fingerprint: "AA".repeat(20), subject: "*.Example.COM", issuer: "Example CA" }],
			}}
		/>,
	);
	expect(screen.getByRole("link", { name: "Look up 192.0.2.9 on VirusTotal" }).getAttribute("href")).toBe(
		"https://www.virustotal.com/gui/ip-address/192.0.2.9",
	);
	const subject = screen.getByRole("link", { name: "Look up *.Example.COM on VirusTotal" });
	expect(subject.getAttribute("href")).toBe("https://www.virustotal.com/gui/domain/example.com");
	expect(subject.getAttribute("target")).toBe("_blank");
	expect(subject.getAttribute("rel")).toBe("noopener noreferrer");
});

it("leaves a subject that is not a hostname unlinked", () => {
	render(
		<HostDetail
			host={{
				...hostShape,
				ip: "192.0.2.9",
				ports: [{ ...portShape, port: 443, fingerprint: "AA".repeat(20), subject: "Internal Root CA" }],
			}}
		/>,
	);
	expect(screen.getByText("Internal Root CA")).toBeTruthy();
	expect(screen.queryByRole("link", { name: /Internal Root CA/ })).toBeNull();
});

it("labels ThreatView Cobalt Strike dates as detections", () => {
	render(
		<SignalReason
			signal={{
				source: "threatview",
				value: "192.0.2.9",
				tag: "C2",
				first_seen: "2026-08-20T15:26:00Z",
			}}
			ip="192.0.2.9"
		/>,
	);
	expect(screen.getByText(/C2 — 192.0.2.9/)).toBeTruthy();
	expect(screen.getByText(/detected 2026-08-20T15:26:00Z/)).toBeTruthy();
});

it("uses identical typography for sortable and inert table headers", () => {
	render(<Table headers={["Sortable", "Inert"]} sort={{ by: "", set: vi.fn(), columns: { Sortable: "value" } }} />);
	const sortable = screen.getByRole("button", { name: "Sortable" });
	const inert = screen.getByRole("columnheader", { name: "Inert" });
	const sortableStyle = getComputedStyle(sortable);
	const inertStyle = getComputedStyle(inert);
	for (const property of ["fontFamily", "fontSize", "fontWeight", "lineHeight", "letterSpacing", "textTransform"] as const) {
		expect(sortableStyle[property], property).toBe(inertStyle[property]);
	}
	expect(sortableStyle.letterSpacing).toBe("0.14em");
	expect(sortableStyle.textTransform).toBe("uppercase");
});

it("prefixes host-only ThreatView indicators with their type", () => {
	render(
		<HostDetail
			host={{
				ip: "192.0.2.9",
				ports: [],
				port_count: 0,
				signals: [
					{
						source: "threatview",
						value: "example.com",
						tag: "Phishing/Malware",
					},
				],
				band: "high",
				checked_at: 1,
				manual: false,
				live_tls: false,
			}}
		/>,
	);
	// Badge first, then tag, then value — the same order the per-certificate reasons use.
	expect(screen.getByText("Phishing/Malware — example.com")).toBeTruthy();
	// The feed line itself carries no link; the record's one lookup covers the address.
	expect(screen.getByRole("link", { name: /on VirusTotal/ }).getAttribute("href")).toBe("https://www.virustotal.com/gui/ip-address/192.0.2.9");
});

it("lays every host-only feed hit out in the same order", () => {
	render(
		<HostDetail
			host={{
				...hostShape,
				ip: "192.0.2.9",
				ports: [{ ...portShape, band: "high" }],
				port_count: 1,
				signals: [
					{ source: "threatfox", value: "192.0.2.9:443", tag: "win.cobalt_strike", confidence_level: 75 },
					{ source: "threatview", value: "example.com", tag: "Phishing/Malware" },
				],
			}}
		/>,
	);
	// Badge, then tag, then value: the source name leads every line whatever the feed is.
	const lines = screen.getAllByText(/win.cobalt_strike|Phishing\/Malware/);
	expect(lines.map((line) => line.textContent)).toEqual([
		"threatfox75%win.cobalt_strike — 192.0.2.9:443  — seen open",
		"threatviewPhishing/Malware — example.com",
	]);
});

describe("quartile captions", () => {
	it("keeps each caption on its own mark until they would collide", () => {
		// Room for all three: every caption stays centred on its quartile.
		expect(spreadLabels([10, 50, 90], [80, 60, 80], 600)).toEqual([20, 270, 500]);
		// Q1 and the median land a pixel apart, so only the overlap is undone.
		const tight = spreadLabels([48, 50, 95], [80, 60, 80], 600);
		expect(tight[1] - (tight[0] + 80)).toBeGreaterThanOrEqual(8);
		expect(tight[2]).toBe(520);
		// Nothing may start left of the track or run off its right edge.
		const edges = spreadLabels([0, 1, 100], [80, 60, 80], 600);
		expect(edges[0]).toBe(0);
		expect(edges[2] + 80).toBeLessThanOrEqual(600);
	});

	it("keeps the anchor caption on its own mark and pushes the others aside", () => {
		// Same squeeze as above, but the median (index 1) is the anchor now: it must land
		// on its exact centred position, and the quartile beside it gives way instead.
		const anchored = spreadLabels([48, 50, 95], [80, 60, 80], 600, 8, 1);
		expect(anchored[1]).toBe(270);
		expect(anchored[1] - (anchored[0] + 80)).toBeGreaterThanOrEqual(8);
	});
});

describe("dashboard", () => {
	it("observes a short manual scan running before it finishes", async () => {
		vi.useFakeTimers();
		const running: ScanStatus = {
			...scan,
			manual: {
				running: true,
				queued: false,
				kind: "common",
				target_count: 5,
				progress: 36,
				started_at: 1,
				finished_at: 0,
			},
		};
		const finished: ScanStatus = {
			...scan,
			manual: {
				running: false,
				queued: false,
				kind: "common",
				target_count: 5,
				progress: 0,
				started_at: 1,
				finished_at: 2,
			},
		};
		let gets = 0;
		vi.stubGlobal(
			"fetch",
			vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
				if (init?.method === "POST")
					return json({
						...scan,
						manual: {
							running: false,
							queued: true,
							kind: "common",
							target_count: 5,
							progress: 0,
							started_at: 0,
							finished_at: 0,
						},
					});
				gets += 1;
				return json(gets === 1 ? scan : gets === 2 ? running : finished);
			}),
		);

		render(
			<ScanProvider>
				<ScanControls hidden={false} />
			</ScanProvider>,
		);
		await act(async () => {});
		fireEvent.change(screen.getByLabelText("Targets"), {
			target: { value: "192.0.2.8" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Scan common ports" }));
		await act(async () => {});
		expect(screen.getByText("Starting manual scan")).toBeTruthy();

		await act(async () => {
			vi.advanceTimersByTime(1_000);
		});
		expect(screen.getByText("Manual scan in progress")).toBeTruthy();
		expect(screen.getByText(/36\.0%/)).toBeTruthy();

		await act(async () => {
			vi.advanceTimersByTime(1_000);
		});
		expect(gets).toBe(2);
		await act(async () => {
			vi.advanceTimersByTime(9_000);
		});
		expect(screen.getByText("Manual scan idle")).toBeTruthy();
	});

	it("renders hosts and switches page routes", async () => {
		vi.spyOn(window, "scrollX", "get").mockReturnValue(100);
		vi.spyOn(window, "scrollY", "get").mockReturnValue(200);
		const writeText = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			configurable: true,
			value: { writeText },
		});
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const path = String(input);
				if (path === "/api/scan") return json(scan);
				if (path === "/api/ack") return json({});
				if (path.startsWith("/api/hosts?")) return json(hosts("192.0.2.8"));
				if (path.startsWith("/api/jarm?")) return json([]);
				if (path.startsWith("/api/domains?")) return json(domains);
				return json({}, 404);
			}),
		);

		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(await screen.findByRole("button", { name: "Copy IP 192.0.2.8" })).toBeTruthy();
		expect(screen.getByRole("columnheader", { name: "Last observed (UTC)" }).getAttribute("aria-sort")).toBeNull();
		expect(screen.getByRole("columnheader", { name: "Scanned by" })).toBeTruthy();
		expect(screen.getByRole("cell", { name: "Automatic" })).toBeTruthy();
		expect(screen.getByRole("option", { name: "Automatic" })).toBeTruthy();
		const copyIP = screen.getByRole("button", { name: "Copy IP 192.0.2.8" });
		fireEvent.mouseEnter(copyIP.closest(".tooltip") as HTMLElement);
		const topTooltip = document.querySelector("body > .tooltip-top") as HTMLElement;
		expect([topTooltip.style.left, topTooltip.style.top]).toEqual(["100px", "194px"]);
		fireEvent.mouseLeave(copyIP.closest(".tooltip") as HTMLElement);
		const ack = screen.getByRole("button", { name: "Acknowledge 192.0.2.8" });
		fireEvent.mouseEnter(ack.closest(".tooltip") as HTMLElement);
		expect(document.querySelector("body > .tooltip-left")).toBeTruthy();
		fireEvent.click(ack);
		expect(await screen.findByText("Host acknowledged")).toBeTruthy();
		fireEvent.click(copyIP);
		await act(async () => {});
		expect(writeText).toHaveBeenCalledWith("192.0.2.8");
		expect(await screen.findByText("Copied to clipboard")).toBeTruthy();
		expect(document.getElementById("host-detail-0")?.hidden).toBe(true);
		expect(screen.getByRole("link", { name: "threatfox" }).className).toContain("badge-curated");

		const jarm = screen.getByRole("link", { name: "JARM" });
		expect(jarm.getAttribute("href")).toBe("/jarm");
		fireEvent.click(jarm);
		expect(await screen.findByText("No JARM sightings yet.")).toBeTruthy();
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/jarm?"), expect.anything());
		const lifetime = screen.getByRole("columnheader", {
			name: "Lifetime hosts",
		});
		expect(lifetime.getAttribute("aria-sort")).toBeNull();
		fireEvent.click(screen.getByRole("button", { name: "Lifetime hosts" }));
		expect(lifetime.getAttribute("aria-sort")).toBe("ascending");
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/jarm?sort=hosts"), expect.anything());
		fireEvent.click(screen.getByRole("button", { name: "Lifetime hosts" }));
		expect(lifetime.getAttribute("aria-sort")).toBe("descending");
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/jarm?sort=-hosts"), expect.anything());
		fireEvent.click(screen.getByRole("button", { name: "Lifetime hosts" }));
		expect(lifetime.getAttribute("aria-sort")).toBeNull();

		fireEvent.click(screen.getByRole("link", { name: "Domains" }));
		// Every name the endpoint returned for one endpoint lands in a single cell, each one its own lookup.
		const first = await screen.findByRole("link", { name: "Look up c2.example.com on VirusTotal" });
		expect(first.closest("td")?.textContent).toBe("c2.example.com, *.example.com");
		expect(first.getAttribute("href")).toBe("https://www.virustotal.com/gui/domain/c2.example.com");
		expect(screen.getByRole("link", { name: "Look up *.example.com on VirusTotal" }).getAttribute("href")).toBe(
			"https://www.virustotal.com/gui/domain/example.com",
		);
		expect(screen.getByRole("columnheader", { name: "Scanned at (UTC)" })).toBeTruthy();
		expect(screen.getByText(stamp(domains[0].scanned_at))).toBeTruthy();
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/domains?"), expect.anything());
		expect(screen.getByText("3 domains on 2 endpoints")).toBeTruthy();
		expect(screen.getByRole("columnheader", { name: "Address" }).getAttribute("aria-sort")).toBeNull();
		fireEvent.click(screen.getByRole("button", { name: "Domain names" }));
		expect(await screen.findByRole("button", { name: "Copy IP 192.0.2.9" })).toBeTruthy();
		expect(screen.getByRole("columnheader", { name: "Domain names" }).getAttribute("aria-sort")).toBe("ascending");
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/domains?sort=name"), expect.anything());
	});

	it("says the feed-only table is off rather than showing it empty", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) =>
				String(input).startsWith("/api/hosts/feed-only?") ? json({ ...hosts("192.0.2.20"), configured: false, scanned: 0, hosts: [] }) : json({}, 404),
			),
		);
		render(
			<MemoryRouter initialEntries={["/hosts/feed-only"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Set scan.feed_only_targets_file in Settings to enable feed-only matching.")).toBeTruthy();
		expect(screen.queryByRole("columnheader", { name: "Address" })).toBeNull();
	});

	it("renders the feed-only hosts route without scan details and supports paging, details, and bulk ACK", async () => {
		const request = vi.fn((input: RequestInfo | URL) => {
			const path = String(input);
			if (path === "/api/scan") return json(scan);
			if (path === "/api/ack?target=feed-only") return json({ acked: true, updated: 1 });
			if (path.startsWith("/api/hosts/feed-only?")) {
				const page = Number(new URL(path, "https://scanner.test").searchParams.get("page"));
				return json({
					...hosts("192.0.2.20"),
					live_tls: 0,
					page,
					pages: 2,
					hosts: [
						{
							...hosts("192.0.2.20").hosts[0],
							signals: [{ source: "threatfox", value: "192.0.2.20:8443", tag: "C2" }],
						},
					],
				});
			}
			return json({}, 404);
		});
		vi.stubGlobal("fetch", request);
		render(
			<MemoryRouter initialEntries={["/hosts/feed-only"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
				<LocationProbe />
			</MemoryRouter>,
		);

		const address = await screen.findByRole("button", { name: "Copy IP 192.0.2.20" });
		expect(screen.queryByRole("columnheader", { name: "Open ports" })).toBeNull();
		expect(screen.queryByRole("columnheader", { name: "Scanned by" })).toBeNull();
		expect(screen.queryByLabelText("Origin")).toBeNull();
		expect(screen.queryByLabelText("Port")).toBeNull();
		expect(screen.getByRole("link", { name: "Feed-only hosts" }).getAttribute("aria-current")).toBe("page");
		expect(screen.getByRole("link", { name: "Hosts" }).getAttribute("aria-current")).toBeNull();
		// The collapsed menu names the deepest matching route, not its parent.
		expect(document.querySelector("#view-menu > summary")?.textContent).toContain("Feed-only hosts");

		fireEvent.click(address.closest("tr") as HTMLElement);
		expect(screen.getByText("Feed hits on 192.0.2.20")).toBeTruthy();
		expect(screen.queryByText("No open ports recorded.")).toBeNull();
		fireEvent.click(screen.getByLabelText("Select 192.0.2.20"));
		fireEvent.click(screen.getByRole("button", { name: "ACK SELECTED" }));
		expect(await screen.findByText("1 host acknowledged")).toBeTruthy();
		expect(request).toHaveBeenCalledWith("/api/ack?target=feed-only", expect.objectContaining({ method: "POST" }));

		fireEvent.click(screen.getByRole("button", { name: "Next" }));
		expect(screen.getByTestId("location").textContent).toBe("/hosts/feed-only?page=2");
		expect(request).toHaveBeenCalledWith(expect.stringContaining("/api/hosts/feed-only?"), expect.anything());
	});

	it("sends the domain date range as the half-open span of instants the picked days cover", async () => {
		const request = vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json(domains)));
		vi.stubGlobal("fetch", request);
		// A day at the end of a month, so a "to" bound that did not roll the month over would show.
		render(
			<MemoryRouter initialEntries={["/domains?from=2026-09-30&to=2026-09-30"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
				<LocationProbe />
			</MemoryRouter>,
		);
		await screen.findByRole("button", { name: "Copy IP 192.0.2.9" });
		const sent = new URL(
			[...request.mock.calls].map(([input]) => String(input)).find((value) => value.startsWith("/api/domains?")) as string,
			"https://scanner.test",
		).searchParams;
		// The one day picked is a whole day wide, and it is the same day whatever zone the browser
		// runs in: the server is handed instants, never a date to place in a timezone of its own.
		expect(Number(sent.get("from"))).toBe(Date.UTC(2026, 8, 30) / 1000);
		expect(Number(sent.get("before")) - Number(sent.get("from"))).toBe(86_400);
		expect(sent.has("to")).toBe(false);
		expect((screen.getByLabelText("From") as HTMLInputElement).value).toBe("2026-09-30");
		// Neither end may cross the other, so the picker cannot ask for a range that holds nothing.
		expect((screen.getByLabelText("To") as HTMLInputElement).min).toBe("2026-09-30");

		fireEvent.click(screen.getByRole("button", { name: "TODAY" }));
		const stamped = utcDay(new Date());
		expect(screen.getByTestId("location").textContent).toBe(`/domains?from=${stamped}&to=${stamped}`);

		fireEvent.click(screen.getByRole("button", { name: "CLEAR" }));
		expect(screen.getByTestId("location").textContent).toBe("/domains");
		expect(screen.queryByRole("button", { name: "CLEAR" })).toBeNull();
	});

	it("cycles every sortable header through ascending, descending, and none", async () => {
		const request = vi.fn((input: RequestInfo | URL) => {
			const path = String(input);
			if (path === "/api/scan") return json(scan);
			if (path.startsWith("/api/hosts?")) return json(hosts("192.0.2.8"));
			if (path.startsWith("/api/domains?") || path.startsWith("/api/jarm?")) return json([]);
			return json({}, 404);
		});
		vi.stubGlobal("fetch", request);
		const views: [string, string, [string, string][]][] = [
			[
				"hosts",
				"/api/hosts?",
				[
					["Address", "ip"],
					["Open ports", "ports"],
					["Band", "band"],
					["Reason", "reasons"],
					["Last observed (UTC)", "recent"],
				],
			],
			[
				"domains",
				"/api/domains?",
				[
					["Address", "ip"],
					["Port", "port"],
					["Domain names", "name"],
					["Scanned at (UTC)", "recent"],
				],
			],
			[
				"jarm",
				"/api/jarm?",
				[
					["Hash", "hash"],
					["Lifetime hosts", "hosts"],
					["First seen (UTC)", "first"],
					["Last seen (UTC)", "recent"],
				],
			],
		];

		for (const [view, api, columns] of views) {
			resetResourceCache();
			const page = render(
				<MemoryRouter initialEntries={[`/${view}`]}>
					<ScanProvider>
						<App />
					</ScanProvider>
					<LocationProbe />
				</MemoryRouter>,
			);
			for (const [label, key] of columns) {
				const header = await screen.findByRole("columnheader", { name: label });
				expect(header.getAttribute("aria-sort")).toBeNull();

				fireEvent.click(screen.getByRole("button", { name: label }));
				expect(header.getAttribute("aria-sort")).toBe("ascending");
				expect(screen.getByTestId("location").textContent).toBe(`/${view}?sort=${key}`);
				await act(async () => {});
				let path = [...request.mock.calls]
					.map(([input]) => String(input))
					.reverse()
					.find((value) => value.startsWith(api));
				expect(new URL(path as string, "https://scanner.test").searchParams.get("sort")).toBe(key);

				fireEvent.click(screen.getByRole("button", { name: label }));
				expect(header.getAttribute("aria-sort")).toBe("descending");
				expect(screen.getByTestId("location").textContent).toBe(`/${view}?sort=-${key}`);
				await act(async () => {});
				path = [...request.mock.calls]
					.map(([input]) => String(input))
					.reverse()
					.find((value) => value.startsWith(api));
				expect(new URL(path as string, "https://scanner.test").searchParams.get("sort")).toBe(`-${key}`);

				fireEvent.click(screen.getByRole("button", { name: label }));
				expect(header.getAttribute("aria-sort")).toBeNull();
				expect(screen.getByTestId("location").textContent).toBe(`/${view}`);
				await act(async () => {});
				path = [...request.mock.calls]
					.map(([input]) => String(input))
					.reverse()
					.find((value) => value.startsWith(api));
				expect(new URL(path as string, "https://scanner.test").searchParams.has("sort")).toBe(false);
			}
			page.unmount();
		}
	});

	it.each([
		["/hosts?sort=-ports", "Open ports", "descending", "/api/hosts?", "-ports"],
		["/hosts?sort=recent", "Last observed (UTC)", "ascending", "/api/hosts?", "recent"],
		["/domains?sort=name", "Domain names", "ascending", "/api/domains?", "name"],
		["/domains?sort=-ip", "Address", "descending", "/api/domains?", "-ip"],
		["/jarm?sort=hosts", "Lifetime hosts", "ascending", "/api/jarm?", "hosts"],
		["/jarm?sort=-hosts", "Lifetime hosts", "descending", "/api/jarm?", "-hosts"],
	])("reads the direction off the sort prefix for %s", async (route, headerName, ariaSort, api, sort) => {
		const request = vi.fn((input: RequestInfo | URL) => {
			const path = String(input);
			if (path === "/api/scan") return json(scan);
			if (path.startsWith("/api/hosts?")) return json(hosts("192.0.2.8"));
			return json([]);
		});
		vi.stubGlobal("fetch", request);
		render(
			<MemoryRouter initialEntries={[route]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect((await screen.findByRole("columnheader", { name: headerName })).getAttribute("aria-sort")).toBe(ariaSort);
		const path = [...request.mock.calls].map(([input]) => String(input)).find((value) => value.startsWith(api));
		const query = new URL(path as string, "https://scanner.test").searchParams;
		expect(query.get("sort")).toBe(sort);
	});

	it("filters hosts from the severity summary tiles", async () => {
		const request = vi.fn((input: RequestInfo | URL) => {
			if (String(input) === "/api/scan") return json(scan);
			if (String(input).startsWith("/api/hosts?")) return json(hosts("192.0.2.8"));
			return json({}, 404);
		});
		vi.stubGlobal("fetch", request);

		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		const high = await screen.findByRole("button", { name: "1 High" });
		expect(screen.queryByRole("button", { name: /Observed hosts/ })).toBeNull();

		fireEvent.click(high);
		expect(high.getAttribute("aria-pressed")).toBe("true");
		expect(request).toHaveBeenLastCalledWith(expect.stringContaining("band=high&size=50&page=1"), expect.anything());
		expect((screen.getByLabelText("High") as HTMLInputElement).checked).toBe(true);
		expect((screen.getByLabelText("Low") as HTMLInputElement).checked).toBe(false);

		fireEvent.click(high);
		expect(high.getAttribute("aria-pressed")).toBe("false");
		expect(request).toHaveBeenLastCalledWith(expect.stringContaining("band=high&band=low&band=clean"), expect.anything());

		fireEvent.click(screen.getByRole("button", { name: "0 Low" }));
		expect(request).toHaveBeenLastCalledWith(expect.stringContaining("band=low&size=50&page=1"), expect.anything());
		fireEvent.click(screen.getByRole("button", { name: "0 Acknowledged" }));
		expect(request).toHaveBeenLastCalledWith(expect.stringContaining("band=ack&size=50&page=1"), expect.anything());
	});

	it("hydrates host filters from the URL and preserves them across a reload", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json(hosts("192.0.2.8")))),
		);
		const url = "/hosts?q=needle&band=ack&origin=manual&port=8443&sort=ip&size=25&page=2";
		const first = render(
			<MemoryRouter initialEntries={[url]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		await screen.findByRole("button", { name: "Copy IP 192.0.2.8" });
		expect((screen.getByLabelText("Search") as HTMLInputElement).value).toBe("needle");
		expect((screen.getByLabelText("Acknowledged") as HTMLInputElement).checked).toBe(true);
		expect((screen.getByLabelText("Origin") as HTMLSelectElement).value).toBe("manual");
		expect((screen.getByLabelText("Port") as HTMLInputElement).value).toBe("8443");
		expect((screen.getByLabelText("Rows per page") as HTMLSelectElement).value).toBe("25");
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("q=needle&band=ack&origin=manual&port=8443&sort=ip&size=25&page=2"), expect.anything());

		first.unmount();
		render(
			<MemoryRouter initialEntries={[url]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		await screen.findByRole("button", { name: "Copy IP 192.0.2.8" });
		expect((screen.getByLabelText("Search") as HTMLInputElement).value).toBe("needle");
		expect((screen.getByLabelText("Acknowledged") as HTMLInputElement).checked).toBe(true);
	});

	it("clears host filters and resets their page", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json(hosts("192.0.2.8")))),
		);
		render(
			<MemoryRouter initialEntries={["/hosts?band=ack&origin=manual&port=8443&page=2"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
				<LocationProbe />
			</MemoryRouter>,
		);
		await screen.findByRole("button", { name: "Copy IP 192.0.2.8" });
		expect(document.querySelector(".hosts-bar")).toBeTruthy();
		const groups = [...document.querySelectorAll(".filter-controls > *"), document.querySelector(".hosts-bar .bulk")];
		expect(groups.every((group) => group && getComputedStyle(group).height === "28px")).toBe(true);
		expect(document.querySelector(".checks > .bar-label")?.textContent).toBe("Band");
		fireEvent.click(screen.getByRole("button", { name: "CLEAR" }));
		expect(screen.getByTestId("location").textContent).toBe("/hosts");
		expect((screen.getByLabelText("High") as HTMLInputElement).checked).toBe(true);
		expect((screen.getByLabelText("Origin") as HTMLSelectElement).value).toBe("");
		expect((screen.getByLabelText("Port") as HTMLInputElement).value).toBe("");
	});

	it("collapses host filters at the mobile breakpoint", async () => {
		vi.stubGlobal(
			"matchMedia",
			vi.fn(() => ({
				matches: true,
				addEventListener: vi.fn(),
				removeEventListener: vi.fn(),
			})),
		);
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json(hosts("192.0.2.8")))),
		);
		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		await screen.findByRole("button", { name: "Copy IP 192.0.2.8" });
		const filters = document.querySelector(".filter-disclosure") as HTMLDetailsElement;
		expect(filters.open).toBe(false);
		fireEvent.click(screen.getByText("Filters"));
		expect(filters.open).toBe(true);
	});

	it("keeps an empty band selection distinct in the URL and API request", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json(hosts("192.0.2.8")))),
		);
		render(
			<MemoryRouter initialEntries={["/hosts?band=high"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
				<LocationProbe />
			</MemoryRouter>,
		);
		await screen.findByRole("button", { name: "Copy IP 192.0.2.8" });
		fireEvent.click(screen.getByLabelText("High"));
		expect(screen.getByTestId("location").textContent).toBe("/hosts?band=");
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/hosts?band=&size=50&page=1"), expect.anything());
		expect((screen.getByLabelText("High") as HTMLInputElement).checked).toBe(false);
		fireEvent.click(screen.getByLabelText("High"));
		expect(screen.getByTestId("location").textContent).toBe("/hosts?band=high");
	});

	it("resets paging when a filter changes and lets the pager write it", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				if (String(input) === "/api/scan") return json(scan);
				const page = Number(new URL(String(input), "https://scanner.test").searchParams.get("page"));
				return json({ ...hosts("192.0.2.8"), page, pages: 3 });
			}),
		);
		render(
			<MemoryRouter initialEntries={["/hosts?page=2"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
				<LocationProbe />
			</MemoryRouter>,
		);
		expect(await screen.findByText("Page 2 of 3")).toBeTruthy();
		fireEvent.change(screen.getByLabelText("Origin"), {
			target: { value: "manual" },
		});
		expect(screen.getByTestId("location").textContent).toBe("/hosts?origin=manual");
		expect(await screen.findByText("Page 1 of 3")).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: "Next" }));
		expect(screen.getByTestId("location").textContent).toBe("/hosts?origin=manual&page=2");
	});

	it("falls back from invalid URL controls and trusts the server's clamped page", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json({ ...hosts("192.0.2.8"), page: 17, pages: 17 }))),
		);
		render(
			<MemoryRouter initialEntries={["/hosts?sort=nonsense&origin=evil&size=999&page=999"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Page 17 of 17")).toBeTruthy();
		expect((screen.getByLabelText("Origin") as HTMLSelectElement).value).toBe("");
		expect((screen.getByLabelText("Rows per page") as HTMLSelectElement).value).toBe("50");
		expect(screen.getByRole("columnheader", { name: "Last observed (UTC)" }).getAttribute("aria-sort")).toBeNull();
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("size=50&page=999"), expect.anything());
	});

	it("debounces search without eating newer input and follows history", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json(hosts("192.0.2.8")))),
		);
		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
				<LocationProbe />
			</MemoryRouter>,
		);
		await screen.findByRole("button", { name: "Copy IP 192.0.2.8" });
		const search = screen.getByLabelText("Search") as HTMLInputElement;
		fireEvent.change(search, { target: { value: "a" } });
		await act(async () => new Promise((resolve) => setTimeout(resolve, 220)));
		expect(screen.getByTestId("location").textContent).toBe("/hosts?q=a");
		fireEvent.change(search, { target: { value: "ab" } });
		await act(async () => {});
		expect(search.value).toBe("ab");
		await act(async () => new Promise((resolve) => setTimeout(resolve, 220)));
		expect(screen.getByTestId("location").textContent).toBe("/hosts?q=ab");
		fireEvent.click(screen.getByRole("button", { name: "History back" }));
		expect(search.value).toBe("a");
		fireEvent.click(screen.getByRole("button", { name: "History back" }));
		expect(search.value).toBe("");
		fireEvent.click(screen.getByRole("button", { name: "History forward" }));
		expect(search.value).toBe("a");
	});

	it("ignores the aborted StrictMode request when it finishes last", async () => {
		let finishFirst: (response: Response) => void = () => {};
		let finishSecond: (response: Response) => void = () => {};
		const request = vi.fn(
			() =>
				new Promise<Response>((resolve) => {
					if (request.mock.calls.length === 1) finishFirst = resolve;
					else finishSecond = resolve;
				}),
		);
		vi.stubGlobal("fetch", request);
		render(
			<StrictMode>
				<MemoryRouter initialEntries={["/hosts"]}>
					<Hosts />
				</MemoryRouter>
			</StrictMode>,
		);
		expect(request).toHaveBeenCalledTimes(2);
		await act(async () => {
			finishSecond(await json(hosts("192.0.2.9")));
		});
		expect(await screen.findByRole("button", { name: "Copy IP 192.0.2.9" })).toBeTruthy();
		await act(async () => {
			finishFirst(await json(hosts("192.0.2.8")));
		});
		expect(screen.queryByRole("button", { name: "Copy IP 192.0.2.8" })).toBeNull();
	});

	it("shows cached hosts while refreshing them", async () => {
		let hostRequests = 0;
		let finishRefresh: (response: Response) => void = () => {};
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const path = String(input);
				if (path === "/api/scan") return json(scan);
				if (path.startsWith("/api/jarm?")) return json([]);
				if (path.startsWith("/api/hosts?")) {
					hostRequests += 1;
					if (hostRequests === 1) return json(hosts("192.0.2.8"));
					return new Promise<Response>((resolve) => {
						finishRefresh = resolve;
					});
				}
				return json({}, 404);
			}),
		);

		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(await screen.findByRole("button", { name: "Copy IP 192.0.2.8" })).toBeTruthy();
		fireEvent.click(screen.getByRole("link", { name: "JARM" }));
		expect(await screen.findByText("No JARM sightings yet.")).toBeTruthy();

		fireEvent.click(screen.getByRole("link", { name: "Hosts" }));
		expect(screen.getByRole("button", { name: "Copy IP 192.0.2.8" })).toBeTruthy();
		expect(hostRequests).toBe(2);

		await act(async () => {
			finishRefresh(await json(hosts("192.0.2.9")));
		});
		expect(await screen.findByRole("button", { name: "Copy IP 192.0.2.9" })).toBeTruthy();
	});

	it("keeps the newest totals when a filter goes back to a view it has already loaded", async () => {
		let totals = { high: 1, acked: 0 };
		let holdRequest = false;
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const path = String(input);
				if (path === "/api/scan") return json(scan);
				if (!path.startsWith("/api/hosts?")) return json({}, 404);
				if (holdRequest) return new Promise<Response>(() => {});
				return json({ ...hosts("192.0.2.8"), ...totals });
			}),
		);

		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		// The acknowledged filter is loaded once and left again, so its response is the stale one.
		expect(await screen.findByRole("button", { name: "1 High" })).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: "0 Acknowledged" }));
		expect(await screen.findByRole("button", { name: "1 High" })).toBeTruthy();

		// The host is acknowledged, and the next response says so.
		totals = { high: 0, acked: 1 };
		fireEvent.click(screen.getByRole("button", { name: "0 Acknowledged" }));
		expect(await screen.findByRole("button", { name: "0 High" })).toBeTruthy();

		// Going back to the acknowledged filter must not count the totals back to what that filter
		// last saw while its own response is in flight.
		holdRequest = true;
		fireEvent.click(screen.getByRole("button", { name: "1 Acknowledged" }));
		await act(async () => {});
		expect(screen.getByRole("button", { name: "0 High" })).toBeTruthy();
		expect(screen.getByRole("button", { name: "1 Acknowledged" })).toBeTruthy();
	});

	it("says it is updating while a filter change is in flight, but not while polling", async () => {
		vi.useFakeTimers();
		let holdRequest = false;
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const path = String(input);
				if (path === "/api/scan") return json(scan);
				if (!path.startsWith("/api/hosts?")) return json({}, 404);
				if (holdRequest) return new Promise<Response>(() => {});
				return json(hosts("192.0.2.8"));
			}),
		);

		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		await act(async () => {});
		const tally = () => document.querySelector(".hosts-bar .count")?.textContent;
		expect(tally()).toBe("1 hosts");

		// A filter change leaves the previous filter's rows on screen, so the count has to say that
		// the ones being asked for have not arrived.
		holdRequest = true;
		fireEvent.click(screen.getByRole("button", { name: "0 Acknowledged" }));
		await act(async () => {});
		expect(tally()).toBe("Updating…");

		// The response for that filter lands and the count settles back to a real tally.
		holdRequest = false;
		await act(async () => {
			vi.advanceTimersByTime(10_000);
		});
		expect(tally()).toBe("1 hosts");

		// A poll re-fetches the path already on screen. Those rows are the right ones, so the count
		// must not flicker every ten seconds.
		holdRequest = true;
		await act(async () => {
			vi.advanceTimersByTime(10_000);
		});
		expect(tally()).toBe("1 hosts");
	});

	it("reloads editing views instead of restoring form data", async () => {
		const saved: SettingsResponse = { config, threatfox_auth_key_set: false };
		const updated: SettingsResponse = {
			config: { ...config, config: { ...config.config, refresh_seconds: 90 } },
			threatfox_auth_key_set: false,
		};
		let settingsRequests = 0;
		let finishSettings: (response: Response) => void = () => {};
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const path = String(input);
				if (path === "/api/scan") return json(scan);
				if (path.startsWith("/api/hosts?")) return json(hosts("192.0.2.8"));
				if (path === "/api/settings") {
					settingsRequests += 1;
					if (settingsRequests === 1) return json(saved);
					return new Promise<Response>((resolve) => {
						finishSettings = resolve;
					});
				}
				return json({}, 404);
			}),
		);

		render(
			<MemoryRouter initialEntries={["/settings"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(((await screen.findByLabelText("refresh_seconds")) as HTMLInputElement).value).toBe("60");
		fireEvent.click(screen.getByRole("link", { name: "Hosts" }));
		expect(await screen.findByRole("button", { name: "Copy IP 192.0.2.8" })).toBeTruthy();
		fireEvent.click(screen.getByRole("link", { name: "Settings" }));

		expect(screen.getByText("Loading...")).toBeTruthy();
		expect(screen.queryByLabelText("refresh_seconds")).toBeNull();
		await act(async () => {
			finishSettings(await json(updated));
		});
		expect(((await screen.findByLabelText("refresh_seconds")) as HTMLInputElement).value).toBe("90");
	});

	it("renders log and targets routes with their page-owned resources", async () => {
		await import("./pages/Targets");
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const path = String(input);
				if (path === "/api/scan") return json(scan);
				if (path.startsWith("/api/logs?"))
					return json([
						{
							at: 1_700_000_000,
							level: "INFO",
							msg: "scan complete",
							attrs: "hosts=1",
						},
					]);
				if (path === "/api/targets")
					return json({
						targets: [{ value: "192.0.2.0/24", addresses: 256, covered_by: "", expansion: [], status: "allowed" }],
						scannable: 256,
						targets_file: "scan_targets.json",
					});
				if (path === "/api/targets?target=feed-only") return json({ targets: [], scannable: 0, targets_file: "" });
				return json({}, 404);
			}),
		);
		const log = render(
			<MemoryRouter initialEntries={["/log"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(await screen.findByText("scan complete")).toBeTruthy();
		expect(screen.getByLabelText("Level")).toBeTruthy();
		log.unmount();

		render(
			<MemoryRouter initialEntries={["/targets"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(await screen.findByText("192.0.2.0/24")).toBeTruthy();
		expect(screen.getByText("1 target · 256 addresses in scope")).toBeTruthy();
	});

	it("shows a route fetch failure instead of stale or loading data", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(() => Promise.resolve(new Response("offline", { status: 503 }))),
		);
		render(
			<MemoryRouter initialEntries={["/hosts"]}>
				<Hosts />
			</MemoryRouter>,
		);
		expect(await screen.findByText("Cannot reach the scanner: offline")).toBeTruthy();
		expect(screen.queryByText("Loading...")).toBeNull();
	});

	it("clears the JARM blacklist saving status after a successful add", async () => {
		const hash = "a".repeat(62);
		let gets = 0;
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
				if (init?.method === "POST") return json([{ label: "Cobalt", hash }]);
				if (String(input) === "/api/jarm-blacklist") {
					gets += 1;
					return json(gets === 1 ? [] : [{ label: "Cobalt", hash }]);
				}
				return json({}, 404);
			}),
		);

		render(
			<MemoryRouter initialEntries={["/jarm-blacklist"]}>
				<JarmBlacklist />
			</MemoryRouter>,
		);
		fireEvent.change(await screen.findByLabelText("Entries"), {
			target: { value: `Cobalt,${hash}` },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add to blacklist" }));

		expect(await screen.findByText("Entries added.")).toBeTruthy();
		expect(screen.queryByText("Saving…")).toBeNull();
	});

	it("submits settings through React Hook Form and shows server confirmation", async () => {
		const saved: SettingsResponse = {
			config: { ...config, feeds: { domain_ignorelist: ["github.com"] } },
			threatfox_auth_key_set: false,
		};
		const request = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => json(saved));
		vi.stubGlobal("fetch", request);
		render(<SettingsForm data={saved} />);

		fireEvent.change(screen.getByLabelText("refresh_seconds"), {
			target: { value: "90" },
		});
		expect((screen.getByLabelText("domain_ignorelist") as HTMLTextAreaElement).value).toBe("github.com");
		fireEvent.change(screen.getByLabelText("domain_ignorelist"), {
			target: { value: "github.com\nmicrosoft.com" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
		expect(await screen.findByText("Settings saved.")).toBeTruthy();
		const init = request.mock.calls[0]?.[1];
		expect(init).toBeDefined();
		const body = JSON.parse(String(init?.body));
		expect(body.config.refresh_seconds).toBe(90);
		expect(body.feeds.domain_ignorelist).toEqual(["github.com", "microsoft.com"]);
	});

	it("renders analytics without polling it", async () => {
		// Loaded before the clock is faked. The route is lazy, and resolving its chunk needs real I/O
		// that a faked timer can never deliver.
		await import("./pages/Analytics");
		vi.useFakeTimers();
		const copied: string[] = [];
		const writeText = vi.fn().mockRejectedValue(new DOMException("Clipboard blocked", "NotAllowedError"));
		Object.defineProperty(navigator, "clipboard", {
			configurable: true,
			value: { writeText },
		});
		Object.defineProperty(document, "execCommand", {
			configurable: true,
			value: vi.fn(() => {
				copied.push((document.activeElement as HTMLTextAreaElement).value);
				return true;
			}),
		});
		let requests = 0;
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const path = String(input);
				if (path === "/api/scan") return json(scan);
				if (path.startsWith("/api/analytics?")) {
					requests += 1;
					return json(analytics);
				}
				return json({}, 404);
			}),
		);

		render(
			<MemoryRouter initialEntries={["/analytics"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		// waitFor is out under fake timers, so the microtask queue is drained by hand.
		for (let tick = 0; tick < 5; tick += 1) await act(async () => {});
		expect(screen.queryByText("Connection time distribution")).toBeNull();
		expect(screen.getByText("Time spent per stage")).toBeTruthy();
		expect(screen.getByRole("heading", { name: "TCP dial timeout" })).toBeTruthy();
		expect(screen.getByText("Data is combined from 14 full scans in last 30 days; common scans are excluded.")).toBeTruthy();
		expect(screen.getByRole("heading", { name: "TLS handshake timeout" })).toBeTruthy();
		expect(screen.getByRole("heading", { name: "JARM probe timeout" })).toBeTruthy();
		expect(screen.queryByRole("heading", { name: "Ports serving TLS most often" })).toBeNull();
		expect(screen.queryByRole("heading", { name: "TLS ports with rated findings" })).toBeNull();
		expect(screen.getByRole("heading", { name: "Common-port scan coverage" })).toBeTruthy();
		// The two coverage panels are one: the ranked ports carry the in/out marker themselves.
		expect(
			screen.queryByRole("heading", {
				name: "Ports to consider adding to common scans",
			}),
		).toBeNull();
		// The configured common scan would reach 4 of the 10 rated endpoints the full scans found.
		expect(screen.getByText("31%", { exact: true })).toBeTruthy();
		expect(screen.getByText("4 of 13 HIGH or LOW endpoints sit on a port scanned in the common range")).toBeTruthy();
		// Ports 22 and 8080 have no rated hits, so the strongest later-scanned ports replace them.
		expect(screen.getByText("no rated hits — replace with 4444 (2 HIGH, 1 LOW)")).toBeTruthy();
		expect(screen.getByText("nothing listening — replace with 2222 (1 HIGH, 5 LOW)")).toBeTruthy();
		expect(screen.getAllByText("scanned later — consider adding")).toHaveLength(9);
		const toml = "common_ports = [4444, 443, 2222, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009]";
		expect(screen.getByText(toml)).toBeTruthy();
		expect(document.querySelectorAll(".coverage-table tbody tr")).toHaveLength(12);
		expect(screen.queryByRole("row", { name: /^9999 / })).toBeNull();
		expect(screen.queryByText("9010")).toBeNull();
		fireEvent.click(screen.getByRole("button", { name: "Copy suggested ports" }));
		fireEvent.click(screen.getByRole("button", { name: "Copy suggested ports as TOML" }));
		await act(async () => {});
		expect(writeText).toHaveBeenNthCalledWith(1, "4444 443 2222 9001 9002 9003 9004 9005 9006 9007 9008 9009");
		expect(writeText).toHaveBeenNthCalledWith(2, toml);
		expect(copied).toEqual(["4444 443 2222 9001 9002 9003 9004 9005 9006 9007 9008 9009", toml]);
		expect(screen.getByText("table compares the current config with the 12 highest-ranked relevant ports", { exact: false })).toBeTruthy();
		expect(
			screen.getByRole("row", {
				name: "2222 6 1 5 scanned later — consider adding",
			}),
		).toBeTruthy();
		expect(screen.queryByText("missed — add it")).toBeNull();
		expect(screen.queryByText("swept, nothing listening")).toBeNull();
		expect(
			screen.getByRole("img", {
				name: "Dial: minimum 0.50ms, lower quartile 1.2ms, median 4.0ms, upper quartile 8.4ms, maximum 10ms",
			}),
		).toBeTruthy();
		expect(
			screen.getByRole("img", {
				name: "Complete probe: minimum 500ms, lower quartile 900ms, median 1.20s, upper quartile 1.80s, maximum 2.80s",
			}),
		).toBeTruthy();
		expect(screen.getByText("Rejected / not TLS")).toBeTruthy();
		expect(
			screen.getByText("a probe can spend the configured limit connecting and again reading", {
				exact: false,
			}),
		).toBeTruthy();
		expect(screen.getAllByText("50ms", { exact: true })).toHaveLength(3);
		expect(
			screen.getByText("2 attempts reached the real deadline.", {
				exact: false,
			}),
		).toBeTruthy();
		expect(screen.getByText("dial_timeout_ms")).toBeTruthy();
		expect(screen.getByText("tls_timeout_ms")).toBeTruthy();
		expect(screen.getByText("jarm_timeout_ms")).toBeTruthy();
		expect(screen.getByText("jarm_blacklist")).toBeTruthy();
		expect(screen.getByText("feodo")).toBeTruthy();
		expect(screen.getByText("phishing_army")).toBeTruthy();
		expect(screen.getByText("1 matching addresses")).toBeTruthy();
		expect(document.querySelectorAll(".analytics-section")).toHaveLength(3);
		expect(document.querySelectorAll(".timeout-explanation")[0]?.textContent).toContain("a refusal, a reset or no route");
		expect(document.querySelectorAll(".timeout-explanation")[1]?.textContent).toContain("These do not mean the timeout is too low.");
		expect(document.querySelector(".budget-rule")).toBeNull();
		expect(screen.queryByText("Available worker time used")).toBeNull();
		expect(screen.queryByText("Scheduled connection attempts")).toBeNull();
		expect(screen.queryByText("Scheduled open-port rate")).toBeNull();
		const kpis = document.querySelectorAll(".analytics-kpi");
		expect(kpis).toHaveLength(4);
		expect(kpis[2]?.textContent).toContain("4444Port with most HIGH-band hits2 unique endpoints rated HIGH");
		expect(kpis[3]?.textContent).toContain("1.20sMedian complete probe time");
		expect(screen.getByText("Most recent full scan size")).toBeTruthy();
		expect(screen.queryByText("4h12m")).toBeNull();
		expect(screen.queryByText("Who issued the certificates?")).toBeNull();
		expect(screen.queryByText("Ports with strong C2 evidence")).toBeNull();
		expect(document.querySelector(".rank-bar")).toBeNull();
		expect(
			screen.getByText("the full list names 12,431 addresses", {
				exact: false,
			}),
		).toBeTruthy();
		expect(screen.getByLabelText("Period")).toBeTruthy();
		expect(screen.queryByText("Window")).toBeNull();
		expect(getComputedStyle(document.querySelector(".analytics-header") as HTMLElement).alignItems).toBe("center");
		expect(getComputedStyle(document.querySelector(".analytics-period") as HTMLElement).alignItems).toBe("center");
		expect(document.querySelector(".as-of")?.textContent).not.toContain("Last 30 days");
		expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/analytics?period=30d"), expect.anything());

		fireEvent.click(screen.getByRole("button", { name: "Latest vs previous" }));
		expect(screen.getByText("Previous full scan")).toBeTruthy();
		expect(screen.getByText("Latest full scan")).toBeTruthy();
		expect(screen.getByText("Not like-for-like:", { exact: false })).toBeTruthy();
		expect(screen.getByRole("heading", { name: "Complete probe time" })).toBeTruthy();
		expect(screen.getByText("−250ms")).toBeTruthy();
		expect(screen.getByText("−2.0ms")).toBeTruthy();
		const comparisonTables = document.querySelectorAll(".comparison-table");
		expect(comparisonTables).toHaveLength(4);
		for (const table of [...comparisonTables].slice(0, 3)) {
			expect([...table.querySelectorAll("tbody th")].slice(0, 4).map((cell) => cell.textContent)).toEqual([
				"Configured limit",
				"Successful",
				"Failed before deadline",
				"Hit configured timeout",
			]);
		}
		expect([...comparisonTables[3].querySelectorAll("tbody tr")][0]?.textContent).toBe("Successful68+2");
		expect(comparisonTables[3].textContent).not.toMatch(/Configured limit|Failed before deadline|Hit configured timeout|90th percentile/);
		fireEvent.click(screen.getByRole("button", { name: "REFRESH" }));
		for (let tick = 0; tick < 3; tick += 1) await act(async () => {});
		expect(requests).toBe(2);
		fireEvent.click(screen.getByRole("button", { name: "Period totals" }));
		expect(screen.getByRole("heading", { name: "TCP dial timeout" })).toBeTruthy();

		// The page reads a history that moves once a sweep, so it is fetched when opened and left
		// alone after that.
		await act(async () => {
			vi.advanceTimersByTime(60_000);
		});
		expect(requests).toBe(2);
	});

	it.each([
		["/analytics?period=7d", "7d"],
		["/analytics?period=nonsense", "30d"],
		["/analytics?span=all", "30d"],
	])("hydrates the analytics period for %s", async (route, expected) => {
		const request = vi.fn((input: RequestInfo | URL) => {
			const path = String(input);
			if (path === "/api/scan") return json(scan);
			const period = new URL(path, "https://scanner.test").searchParams.get("period") ?? "30d";
			return json({ ...analytics, period });
		});
		vi.stubGlobal("fetch", request);
		render(
			<MemoryRouter initialEntries={[route]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(((await screen.findByLabelText("Period")) as HTMLSelectElement).value).toBe(expected);
		expect(screen.getAllByText("Period", { exact: true })).toHaveLength(1);
		expect(document.querySelector(".as-of")?.textContent).not.toContain("Last");
		const path = [...request.mock.calls].map(([input]) => String(input)).find((value) => value.startsWith("/api/analytics?"));
		const query = new URL(path as string, "https://scanner.test").searchParams;
		expect(query.get("period")).toBe(expected);
		expect(query.has("span")).toBe(false);
	});

	it("shows no changes after the suggested ports are applied", async () => {
		const suggested = new Set([4444, 443, 2222, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009]);
		const applied = {
			...analytics,
			coverage: {
				...analytics.coverage,
				ports: analytics.coverage.ports.map((row) => ({
					...row,
					configured: suggested.has(row.port) || undefined,
				})),
			},
		};
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => (String(input) === "/api/scan" ? json(scan) : json(applied))),
		);

		render(
			<MemoryRouter initialEntries={["/analytics"]}>
				<ScanProvider>
					<App />
				</ScanProvider>
			</MemoryRouter>,
		);
		expect(await screen.findByText("common_ports = [4444, 443, 2222, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009]")).toBeTruthy();
		expect(screen.queryByText("scanned later — consider adding")).toBeNull();
		expect(screen.queryByText(/consider removing/)).toBeNull();
		expect(screen.getAllByText("scanned first")).toHaveLength(12);
	});

	it("renders Badge links safely", () => {
		const open = vi.spyOn(window, "open").mockImplementation(() => null);
		render(<Badge source="tweetfeed" links={["https://one.example", "https://two.example"]} />);
		fireEvent.mouseEnter(screen.getByRole("link").closest(".tooltip") as HTMLElement);
		expect(screen.getByRole("tooltip").textContent).toBe("Open feed source");
		fireEvent.click(screen.getByRole("link"));
		expect(open).toHaveBeenCalledTimes(2);
		expect(screen.getByRole("link").getAttribute("rel")).toBe("noopener noreferrer");
	});

	it("colors only present ThreatFox confidence scores", () => {
		render(
			<>
				<Badge source="threatfox" score={51} />
				<Badge source="threatfox" score={50} />
				<Badge source="threatfox" score={0} />
				<Badge source="threatfox" />
				<Badge source="feodo" />
			</>,
		);
		expect(screen.getByText("51%").classList.contains("band-high")).toBe(true);
		expect(screen.getByText("50%").classList.contains("band-low")).toBe(true);
		expect(screen.getByText("0%").classList.contains("band-low")).toBe(true);
		// A scoreless badge shows no percentage; only ThreatFox ever carries one.
		expect(screen.getAllByText(/%$/)).toHaveLength(3);
		fireEvent.mouseEnter(screen.getByText("51%").closest(".tooltip") as HTMLElement);
		expect(screen.getByRole("tooltip").textContent).toBe("Confidence level");
	});

	it("shows the highest ThreatFox confidence on a host row and individual scores in details", () => {
		const host: Host = {
			...hostShape,
			signals: [
				{ source: "threatfox", value: "192.0.2.9:443", tag: "one", confidence_level: 51 },
				{ source: "threatfox", value: "192.0.2.9:8443", tag: "two", confidence_level: 75 },
			],
		};
		const { unmount } = render(
			<table>
				<tbody>
					<HostRow
						host={host}
						index={0}
						selected={false}
						incompatible={false}
						pending={false}
						failed=""
						onToggle={() => {}}
						onExpand={() => {}}
						onAck={() => Promise.resolve()}
					/>
				</tbody>
			</table>,
		);
		expect(screen.getByText("75%")).toBeTruthy();
		expect(screen.queryByText("51%")).toBeNull();
		unmount();
		render(<HostDetail host={host} />);
		expect(screen.getByText("51%")).toBeTruthy();
		expect(screen.getByText("75%")).toBeTruthy();
	});
});

describe("input helpers", () => {
	it("parses targets and blacklist lines and formats elapsed time", () => {
		expect(parseTarget("192.0.2.8")).toEqual({
			value: "192.0.2.8/32",
			addresses: 1,
			covered_by: "",
			expansion: [],
			status: "unsaved",
		});
		expect(parseTarget("as13335")).toEqual({
			value: "AS13335",
			addresses: 0,
			covered_by: "",
			expansion: [],
			status: "unsaved",
		});
		expect(parseTarget("999.0.0.1")).toBeNull();
		expect(parseEntries("Cobalt, abc\nOther, def")).toEqual([
			{ label: "Cobalt", hash: "abc" },
			{ label: "Other", hash: "def" },
		]);
		expect(() => parseEntries("missing comma")).toThrow("Line 1 must be Label,Hash.");
		expect(elapsed(0, 3670)).toBe("1h1m");
		expect(day(0)).toBe("1970-01-01");
		// UTC, zero-padded and fixed width, so the timestamp columns stay aligned and a date input
		// takes the day without argument. A locale is not asked for the shape.
		const early = new Date(Date.UTC(2026, 0, 5, 9, 5, 3));
		expect(utcDay(early)).toBe("2026-01-05");
		expect(stamp(early.getTime() / 1000)).toBe("2026-01-05 09:05:03");
		expect(stamp(0)).toBe("never");
	});

	it("sends an ASN entered in the Targets editor", async () => {
		const request = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
			json({
				targets: [{ value: "AS13335", addresses: 256, covered_by: "", expansion: [], status: "in scope" }],
				scannable: 256,
				targets_file: "targets.json",
			}),
		);
		vi.stubGlobal("fetch", request);
		render(<TargetEditor data={{ targets: [], scannable: 0, targets_file: "targets.json" }} />);
		fireEvent.change(screen.getByLabelText(/Addresses, CIDRs, or ASNs/), { target: { value: "as13335" } });
		fireEvent.click(screen.getByRole("button", { name: "Add targets" }));
		expect(screen.getByText("AS13335")).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: "Save targets" }));
		await screen.findByText("Targets saved. The next sweep uses them.");
		expect(JSON.parse(String(request.mock.calls[0]?.[1]?.body))).toEqual({ targets: ["AS13335"] });
	});

	it("expands and collapses ASN prefixes without remove controls", () => {
		render(
			<TargetEditor
				data={{
					targets: [
						{
							value: "AS13335",
							addresses: 512,
							covered_by: "",
							expansion: [
								{ value: "1.0.0.0/24", addresses: 256, status: "in scope" },
								{ value: "1.1.1.0/24", addresses: 256, status: "denied" },
							],
							status: "in scope",
						},
					],
					scannable: 256,
					targets_file: "targets.json",
				}}
			/>,
		);
		const toggle = screen.getByRole("button", { name: "Expand AS13335 prefixes" });
		expect(toggle.getAttribute("aria-expanded")).toBe("false");
		expect(screen.queryByText("1.0.0.0/24")).toBeNull();
		fireEvent.click(toggle);
		expect(toggle.getAttribute("aria-expanded")).toBe("true");
		const child = screen.getByText("1.0.0.0/24").closest("tr");
		expect(child?.querySelector("button")).toBeNull();
		expect(screen.getByText("denied")).toBeTruthy();
		fireEvent.click(toggle);
		expect(toggle.getAttribute("aria-expanded")).toBe("false");
		expect(screen.queryByText("1.0.0.0/24")).toBeNull();
	});

	it("orders badge sources curated -> crowd -> local so truncation drops the least trustworthy first", () => {
		expect(sortSourcesByBand(["self_signed", "tweetfeed", "threatfox", "cert_validity", "feodo"])).toEqual([
			"threatfox",
			"feodo",
			"tweetfeed",
			"self_signed",
			"cert_validity",
		]);
		expect(sortSourcesByBand(["expired_cert", "long_validity"])).toEqual(["expired_cert", "long_validity"]);
	});
});
