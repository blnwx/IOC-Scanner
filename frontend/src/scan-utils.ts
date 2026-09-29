import type { ScanPass } from "./types";
import { elapsed, stamp } from "./utils";

export const EMPTY_PASS: ScanPass = {
	running: false,
	queued: false,
	kind: "",
	target_count: 0,
	progress: 0,
	started_at: 0,
	finished_at: 0,
};

export function scanPassText(name: "scheduled" | "manual", pass: ScanPass, now: number) {
	const label = name === "scheduled" ? "Scheduled" : "Manual";
	const ports = pass.kind === "common" ? "common ports" : "all ports";
	const targets = `${pass.target_count.toLocaleString()} ${pass.target_count === 1 ? "target" : "targets"}`;
	const coverage = `${targets} · ${ports}`;
	if (pass.queued)
		return {
			state: "Starting manual scan",
			detail: `${coverage} · waiting to start`,
			busy: true,
		};
	if (pass.running)
		return {
			state: `${label} scan in progress`,
			detail: `${coverage} · ${pass.progress.toFixed(1)}% · ${elapsed(pass.started_at, now)} elapsed`,
			busy: true,
		};
	return {
		state: `${label} scan idle`,
		detail: pass.finished_at ? `last scan finished ${stamp(pass.finished_at)} UTC` : "no scan yet",
		busy: false,
	};
}
