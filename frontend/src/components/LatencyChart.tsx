import type { Latency } from "../types";
import { Panel } from "./Panel";

export function duration(microseconds: number, available = true): string {
	if (!available) return "—";
	const milliseconds = microseconds / 1000;
	if (milliseconds < 1) return `${milliseconds.toFixed(2)}ms`;
	if (milliseconds < 10) return `${milliseconds.toFixed(1)}ms`;
	if (milliseconds < 1000) return `${Math.round(milliseconds).toLocaleString()}ms`;
	return `${(milliseconds / 1000).toFixed(2)}s`;
}

function percentage(part: number, whole: number): string {
	return whole ? `${((part / whole) * 100).toFixed(1)}%` : "—";
}

interface LatencyChartProps {
	title: string;
	note: string;
	configKey: string;
	successLabel: string;
	failureLabel: string;
	failureNote: string;
	latency: Latency;
}

export function LatencyChart({ title, note, configKey, successLabel, failureLabel, failureNote, latency }: LatencyChartProps) {
	const attempts = latency.successes + latency.failures + latency.timeouts;
	if (!attempts)
		return (
			<Panel title={title} note={note}>
				<p className="panel-empty">The first full scan recorded with exact timing will populate this view.</p>
			</Panel>
		);

	return (
		<Panel title={title} note={note}>
			<div className="latency-summary">
				<output>{duration(latency.median_us, Boolean(latency.successes))}</output>
				<span>
					actual median across {latency.successes.toLocaleString()} successful {successLabel}
				</span>
			</div>

			<dl className="latency-facts">
				<div>
					<dt>Actual median</dt>
					<dd>{duration(latency.median_us, Boolean(latency.successes))}</dd>
				</div>
				<div>
					<dt>Actual 90th percentile</dt>
					<dd>{duration(latency.p90_us, Boolean(latency.successes))}</dd>
				</div>
				<div>
					<dt>Configured limit</dt>
					<dd>
						{latency.budget_ms.toLocaleString()}ms<small>{configKey}</small>
					</dd>
				</div>
			</dl>

			<table className="timeout-results">
				<tbody>
					<tr>
						<th scope="row">Successful</th>
						<td>{latency.successes.toLocaleString()}</td>
						<td>{percentage(latency.successes, attempts)}</td>
					</tr>
					<tr>
						<th scope="row">{failureLabel}</th>
						<td>{latency.failures.toLocaleString()}</td>
						<td>{percentage(latency.failures, attempts)}</td>
					</tr>
					<tr className="deadline">
						<th scope="row">Hit configured timeout</th>
						<td>{latency.timeouts.toLocaleString()}</td>
						<td>{percentage(latency.timeouts, attempts)}</td>
					</tr>
				</tbody>
			</table>

			<p className="timeout-explanation">
				<strong>{failureLabel}:</strong> {failureNote}
			</p>
			<p className="timeout-guidance">
				{latency.timeouts
					? `${latency.timeouts.toLocaleString()} attempts reached the real deadline. These are the results that may justify raising ${configKey}; compare the rate after the next full scan.`
					: `No attempts reached the deadline, so this period gives no evidence that ${configKey} needs to be raised.`}
			</p>
		</Panel>
	);
}
