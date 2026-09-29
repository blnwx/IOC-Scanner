import type { Latency, ScanTimeoutAnalytics } from "../types";
import { elapsed } from "../utils";
import { duration } from "./LatencyChart";
import { Panel } from "./Panel";

function rate(value: number, timing: Latency) {
	const total = timing.successes + timing.failures + timing.timeouts;
	return total ? (value / total) * 100 : null;
}

function signed(value: number, format = (n: number) => n.toLocaleString()) {
	if (!value) return "0";
	return `${value > 0 ? "+" : "−"}${format(Math.abs(value))}`;
}

function outcome(value: number, timing: Latency, withRate = true) {
	const percentage = rate(value, timing);
	return `${value.toLocaleString()}${withRate ? ` (${percentage === null ? "—" : `${percentage.toFixed(1)}%`})` : ""}`;
}

function outcomeDelta(latest: number, previous: number, latestTiming: Latency, previousTiming: Latency, withRate = true) {
	const count = signed(latest - previous);
	if (!withRate) return count;
	const latestRate = rate(latest, latestTiming);
	const previousRate = rate(previous, previousTiming);
	return `${count} (${latestRate === null || previousRate === null ? "—" : signed(latestRate - previousRate, (n) => `${n.toFixed(1)}pp`)})`;
}

type TimingKey = "median_us" | "p90_us" | "min_us" | "q1_us" | "q3_us" | "max_us";

interface ComparisonStageProps {
	title: string;
	latest: Latency;
	previous: Latency;
	complete?: boolean;
}

function ComparisonStage({ title, latest, previous, complete = false }: ComparisonStageProps) {
	const timingRows: [string, TimingKey][] = [
		["Median", "median_us"],
		["90th percentile", "p90_us"],
		["Minimum", "min_us"],
		["Lower quartile", "q1_us"],
		["Upper quartile", "q3_us"],
		["Maximum", "max_us"],
	];
	if (complete) timingRows.splice(1, 1);
	const outcomeRows: [string, "successes" | "failures" | "timeouts"][] = [
		["Successful", "successes"],
		["Failed before deadline", "failures"],
		["Hit configured timeout", "timeouts"],
	];
	const timingValue = (timing: Latency, key: TimingKey) => duration(timing[key], Boolean(timing.successes));
	const timingDelta = (key: TimingKey) => (latest.successes && previous.successes ? signed(latest[key] - previous[key], (n) => duration(n)) : "—");

	return (
		<Panel title={title} note="Previous and latest values are shown as recorded; the change is neutral and does not imply causation.">
			<div className="scroller">
				<table className="comparison-table">
					<thead>
						<tr>
							<th>Measure</th>
							<th>Previous</th>
							<th>Latest</th>
							<th>Change</th>
						</tr>
					</thead>
					<tbody>
						{!complete ? (
							<tr>
								<th scope="row">Configured limit</th>
								<td>{previous.budget_ms.toLocaleString()}ms</td>
								<td>{latest.budget_ms.toLocaleString()}ms</td>
								<td>{signed(latest.budget_ms - previous.budget_ms, (n) => `${n.toLocaleString()}ms`)}</td>
							</tr>
						) : null}
						{outcomeRows.slice(0, complete ? 1 : 3).map(([label, key]) => (
							<tr key={key}>
								<th scope="row">{label}</th>
								<td>{outcome(previous[key], previous, !complete)}</td>
								<td>{outcome(latest[key], latest, !complete)}</td>
								<td>{outcomeDelta(latest[key], previous[key], latest, previous, !complete)}</td>
							</tr>
						))}
						{timingRows.map(([label, key]) => (
							<tr key={key}>
								<th scope="row">{label}</th>
								<td>{timingValue(previous, key)}</td>
								<td>{timingValue(latest, key)}</td>
								<td>{timingDelta(key)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</Panel>
	);
}

function ScanSummary({ label, scan }: { label: string; scan: ScanTimeoutAnalytics }) {
	return (
		<div className="comparison-scan">
			<strong>{label}</strong>
			<time>{new Date(scan.started_at * 1000).toLocaleString()}</time>
			<span>
				{scan.source} · {scan.targets.toLocaleString()} targets · {scan.max_workers.toLocaleString()} workers · {elapsed(0, scan.elapsed_ms / 1000)}
			</span>
		</div>
	);
}

export function ScanComparison({ latest, previous }: { latest: ScanTimeoutAnalytics; previous: ScanTimeoutAnalytics }) {
	const mismatch = latest.source !== previous.source || latest.targets !== previous.targets || latest.max_workers !== previous.max_workers;
	return (
		<div className="performance-stack">
			<div className="comparison-scans">
				<ScanSummary label="Previous full scan" scan={previous} />
				<ScanSummary label="Latest full scan" scan={latest} />
			</div>
			{mismatch ? (
				<p className="comparison-warning">
					Not like-for-like: scan origin, target count, or worker count changed. Read the deltas as context, not as the effect of timeout settings.
				</p>
			) : null}
			<div className="comparison-grid">
				<ComparisonStage title="TCP dial timeout" latest={latest.dial} previous={previous.dial} />
				<ComparisonStage title="TLS handshake timeout" latest={latest.tls} previous={previous.tls} />
				<ComparisonStage title="JARM probe timeout" latest={latest.jarm} previous={previous.jarm} />
				<ComparisonStage title="Complete probe time" latest={latest.complete} previous={previous.complete} complete />
			</div>
		</div>
	);
}
