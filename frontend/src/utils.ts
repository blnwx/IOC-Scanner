import { toast } from "sonner";
import type { JarmBlacklistEntry, TargetRow } from "./types";

export async function copyText(value: string): Promise<boolean> {
	let copied = false;
	try {
		if (navigator.clipboard) {
			await navigator.clipboard.writeText(value);
			copied = true;
		}
	} catch {
		// Clipboard access is commonly blocked on non-HTTPS origins; use the native fallback below.
	}

	if (!copied) {
		const field = document.createElement("textarea");
		field.value = value;
		field.readOnly = true;
		field.style.cssText = "position:fixed;opacity:0;pointer-events:none";
		document.body.append(field);
		field.focus();
		field.select();
		try {
			copied = document.execCommand("copy");
		} catch {
			copied = false;
		} finally {
			field.remove();
		}
	}
	if (copied) toast.success("Copied to clipboard");
	else toast.error("Could not copy to clipboard");
	return copied;
}

function pad(value: number): string {
	return String(value).padStart(2, "0");
}

// Every timestamp on the dashboard is UTC, and the columns say so. The scan rows are read beside
// feeds, VirusTotal lookups and incident timelines that are all quoted that way, and a filter URL
// pasted to someone else has to select the same span for them as it did here. Built from the UTC
// getters rather than a locale, which would be trusting one to keep producing this shape.
export function utcDay(at: Date): string {
	return `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}`;
}

// Fixed width, so the timestamp columns line up.
export function stamp(seconds: number) {
	if (!seconds) return "never";
	const at = new Date(seconds * 1000);
	return `${utcDay(at)} ${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())}:${pad(at.getUTCSeconds())}`;
}

// The domains filter picks days; the API is handed the instants they cover, so a day is midnight to
// midnight UTC whatever zone the browser sits in. Adding to the day component is what rolls a month
// or a year over.
export function dayStart(date: string, plusDays = 0): number {
	const [year, month, day] = date.split("-").map(Number);
	if (!year || !month || !day) return 0;
	return Date.UTC(year, month - 1, day + plusDays) / 1000;
}

export function today(): string {
	return utcDay(new Date());
}

export function day(seconds: number) {
	return utcDay(new Date(seconds * 1000));
}

export function groups(hex: string) {
	return hex ? (hex.match(/../g) || []).join(":") : "—";
}

export function elapsed(started: number, now = Date.now() / 1000): string {
	let seconds = Math.max(0, Math.floor(now - started));
	const parts: string[] = [];
	for (const [size, suffix] of [
		[86400, "d"],
		[3600, "h"],
		[60, "m"],
		[1, "s"],
	] as const) {
		const value = Math.floor(seconds / size);
		if (value) parts.push(`${value}${suffix}`);
		seconds %= size;
	}
	return parts.slice(0, 2).join("") || "0s";
}

// Whitespace- or comma-separated input, as every multi-value field on the dashboard accepts it.
export function items(value: string) {
	return value.split(/[\s,]+/).filter(Boolean);
}

const TARGET = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;

export function parseTarget(value: string): TargetRow | null {
	const trimmed = value.trim();
	if (/^AS\d{1,10}$/i.test(trimmed)) {
		return { value: trimmed.toUpperCase(), addresses: 0, covered_by: "", expansion: [], status: "unsaved" };
	}
	const match = TARGET.exec(trimmed);
	if (!match || match.slice(1, 5).some((part) => Number(part) > 255)) return null;
	const bits = match[5] === undefined ? 32 : Number(match[5]);
	if (bits > 32) return null;
	return {
		value: match[5] === undefined ? `${trimmed}/32` : trimmed,
		addresses: 2 ** (32 - bits),
		covered_by: "",
		expansion: [],
		status: "unsaved",
	};
}

export function parseEntries(value: string): JarmBlacklistEntry[] {
	return value
		.split(/\r?\n/)
		.filter((line) => line.trim())
		.map((line, index) => {
			const fields = line.split(",");
			if (fields.length !== 2) throw new Error(`Line ${index + 1} must be Label,Hash.`);
			return { label: fields[0].trim(), hash: fields[1].trim() };
		});
}
