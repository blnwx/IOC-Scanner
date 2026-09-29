import {
	allowed,
	type Config,
	DEFAULT_PERIOD,
	DEFAULT_SIZE,
	DOMAIN_SORTS,
	FEED_ONLY_HOST_SORTS,
	HOST_SORTS,
	JARM_SORTS,
	type JarmBlacklistEntry,
	LOG_LEVELS,
	ORIGINS,
	PAGE_SIZES,
	PERIOD_VALUES,
	type ScanStatus,
	type SettingsResponse,
	selectedBands,
	type TargetsResponse,
	type View,
} from "./types";
import { dayStart } from "./utils";

async function responseError(response: Response): Promise<Error> {
	const text = (await response.text()).trim();
	return new Error(text || `request failed with ${response.status}`);
}

export async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
	const response = await fetch(path, { signal });
	if (!response.ok) throw await responseError(response);
	return response.json() as Promise<T>;
}

export async function sendJSON<T>(path: string, method: string, body: unknown): Promise<T> {
	const response = await fetch(path, {
		method,
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	if (!response.ok) throw await responseError(response);
	return response.json() as Promise<T>;
}

// Only a sort the table actually offers travels; its "-" prefix carries the direction.
function addSort(params: URLSearchParams, search: URLSearchParams, sorts: readonly string[]) {
	const sort = search.get("sort") ?? "";
	if (sorts.includes(sort.replace(/^-/, ""))) params.set("sort", sort);
}

export function dashboardPath(view: View, search: URLSearchParams, feedOnly = false): string {
	const params = new URLSearchParams();
	const query = search.get("q")?.trim();
	if (query) params.set("q", query);
	if (view === "hosts") {
		for (const band of selectedBands(search)) params.append("band", band);
		if (!feedOnly) {
			const origin = allowed(search.get("origin"), ORIGINS);
			if (origin) params.set("origin", origin);
			const port = search.get("port")?.trim();
			if (port) params.set("port", port);
		}
		addSort(params, search, feedOnly ? FEED_ONLY_HOST_SORTS : HOST_SORTS);
		params.set("size", allowed(search.get("size"), PAGE_SIZES, DEFAULT_SIZE));
		// Left as typed: the handler clamps it to the real page count, which only it knows.
		params.set("page", search.get("page") || "1");
		return `/api/hosts${feedOnly ? "/feed-only" : ""}?${params}`;
	}
	if (view === "analytics") {
		params.set("period", allowed(search.get("period"), PERIOD_VALUES, DEFAULT_PERIOD));
		return `/api/analytics?${params}`;
	}
	if (view === "domains") {
		addSort(params, search, DOMAIN_SORTS);
		// The URL carries the two days the operator picked; the handler is sent the half-open span
		// of instants they cover, so the "to" day is included whole.
		const from = dayStart(search.get("from") ?? "");
		const before = dayStart(search.get("to") ?? "", 1);
		if (from) params.set("from", String(from));
		if (before) params.set("before", String(before));
		return `/api/domains?${params}`;
	}
	if (view === "jarm") {
		addSort(params, search, JARM_SORTS);
		return `/api/jarm?${params}`;
	}
	if (view === "jarm-blacklist") return "/api/jarm-blacklist";
	if (view === "log") {
		const level = allowed(search.get("level"), LOG_LEVELS);
		if (level) params.set("level", level);
		return `/api/logs?${params}`;
	}
	return view === "settings" ? "/api/settings" : "/api/targets";
}

export function getScan() {
	return getJSON<ScanStatus>("/api/scan");
}

export function startScan(kind: "common" | "full", targets: string) {
	return sendJSON<ScanStatus>("/api/scan", "POST", { kind, targets });
}

export function acknowledge(body: { ip: string } | { ips: string[]; acked: boolean }, feedOnly = false) {
	return sendJSON<Record<string, unknown>>(`/api/ack${feedOnly ? "?target=feed-only" : ""}`, "POST", body);
}

export function changeBlacklist(method: "POST" | "DELETE", body: JarmBlacklistEntry[] | { hash: string }) {
	return sendJSON<JarmBlacklistEntry[]>("/api/jarm-blacklist", method, body);
}

export function saveSettings(config: Config) {
	return sendJSON<SettingsResponse>("/api/settings", "PUT", config);
}

export function saveTargets(targets: string[], feedOnly = false) {
	return sendJSON<TargetsResponse>(`/api/targets${feedOnly ? "?target=feed-only" : ""}`, "PUT", { targets });
}
