import { useState } from "react";
import { dashboardPath } from "../api";
import { EmptyState } from "../components/EmptyState";
import { duration, LatencyChart } from "../components/LatencyChart";
import { Panel } from "../components/Panel";
import { PortCoverage } from "../components/PortCoverage";
import { ScanComparison } from "../components/ScanComparison";
import { TimingRow } from "../components/TimingRow";
import { useFilters } from "../hooks/useFilters";
import { useResource } from "../hooks/useResource";
import { type AnalyticsResponse, allowed, DEFAULT_PERIOD, PERIOD_VALUES, PERIODS } from "../types";

export { spreadLabels } from "../components/TimingRow";

function Meter({ value }: { value: number }) {
	return (
		<span className="chart-bar" aria-hidden="true">
			<span style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} />
		</span>
	);
}

export function Analytics() {
	const [params, set] = useFilters();
	const period = allowed(params.get("period"), PERIOD_VALUES, DEFAULT_PERIOD);
	const { data, error, reload } = useResource<AnalyticsResponse>(dashboardPath("analytics", params), { poll: false });
	const [compare, setCompare] = useState(false);
	if (!data) return <EmptyState>{error || "Loading..."}</EmptyState>;
	const { coverage } = data;
	const stages = [
		{
			label: "Dial",
			timing: data.dial,
			note: "Opening the TCP connection, on ports that answered.",
		},
		{
			label: "TLS handshake",
			timing: data.tls,
			note: "After the port opened, until the certificate was in hand.",
		},
		{
			label: "JARM probe",
			timing: data.jarm,
			note: "One probe. A fingerprint sends ten of them in sequence.",
		},
		{
			label: "Complete probe",
			timing: data.complete,
			note: "Dial, TLS handshake and all ten JARM probes, where every stage finished.",
		},
	];
	const maxFeed = Math.max(1, ...data.feeds.map((feed) => feed.hosts));
	const periodLabel = PERIODS.find(([value]) => value === data.period)?.[1] ?? "Selected period";
	const highPort = coverage.ports.find((row) => row.high > 0);

	return (
		<div className="analytics-page">
			<header className="analytics-header">
				<h1>Analytics</h1>
				<label className="analytics-period">
					<span>Period</span>
					<select
						value={period}
						onChange={(event) =>
							set({
								period: event.target.value === DEFAULT_PERIOD ? "" : event.target.value,
							})
						}
					>
						{PERIODS.map(([value, label]) => (
							<option key={value} value={value}>
								{label}
							</option>
						))}
					</select>
				</label>
				<p className="as-of">Data through {new Date(data.generated_at * 1000).toLocaleString()}</p>
			</header>

			<div className="analytics-kpis">
				<div className="analytics-kpi">
					<output>{data.cost.passes.toLocaleString()}</output>
					<strong>Scan runs analyzed</strong>
					<span>Only complete 1-65,535 port scans in this period</span>
				</div>
				<div className="analytics-kpi">
					<output>{data.cost.targets.toLocaleString()}</output>
					<strong>Most recent full scan size</strong>
					<span>Target addresses included in that scan</span>
				</div>
				<div className="analytics-kpi">
					<output>{highPort?.port ?? "—"}</output>
					<strong>Port with most HIGH-band hits</strong>
					<span>{highPort ? `${highPort.high.toLocaleString()} unique endpoints rated HIGH` : "No HIGH endpoints in this period"}</span>
				</div>
				<div className="analytics-kpi">
					<output>{duration(data.complete.median_us, Boolean(data.complete.successes))}</output>
					<strong>Median complete probe time</strong>
					<span>Dial, TLS handshake and all ten JARM probes</span>
				</div>
			</div>

			<PortCoverage coverage={coverage} />

			<section className="analytics-section">
				<div className="section-title">
					<h2>Timeouts</h2>
					<div className="timeout-controls">
						<fieldset className="view-toggle" aria-label="Timeout view">
							<button type="button" aria-pressed={!compare} onClick={() => setCompare(false)}>
								Period totals
							</button>
							<button type="button" aria-pressed={compare} onClick={() => setCompare(true)}>
								Latest vs previous
							</button>
						</fieldset>
						{compare ? (
							<button type="button" className="ackbtn" onClick={reload}>
								REFRESH
							</button>
						) : null}
					</div>
				</div>

				{compare ? (
					data.comparison ? (
						<ScanComparison latest={data.comparison.latest} previous={data.comparison.previous} />
					) : (
						<Panel title="Latest vs previous" note="Comparison uses completed 1-65,535 port scans only.">
							<p className="panel-empty">Two completed full scans are required. Finish another full scan, then refresh this view.</p>
						</Panel>
					)
				) : (
					<div className="performance-stack">
						<p className="timeout-period-note">
							Data is combined from {data.cost.passes.toLocaleString()} full scans in {periodLabel.toLowerCase()}; common scans are excluded.
						</p>
						<div className="latency-grid">
							<LatencyChart
								title="TCP dial timeout"
								configKey="dial_timeout_ms"
								note="Every scanned port starts here. Only a dial that ran out the budget is counted as timed out."
								successLabel="connections"
								failureLabel="Refused / unreachable"
								failureNote="The network answered at once with a refusal, a reset or no route. These say nothing about whether the limit is too low."
								latency={data.dial}
							/>
							<LatencyChart
								title="TLS handshake timeout"
								configKey="tls_timeout_ms"
								note="One attempt runs after a TCP port opens. Only a real deadline hit is counted as timed out."
								successLabel="TLS handshakes"
								failureLabel="Rejected / not TLS"
								failureNote="The peer replied before the deadline but did not complete TLS. These do not mean the timeout is too low."
								latency={data.tls}
							/>
							<LatencyChart
								title="JARM probe timeout"
								configKey="jarm_timeout_ms"
								note="JARM runs only after TLS succeeds. Each fingerprint sends ten probes; a probe can spend the configured limit connecting and again reading, so its successful total can exceed that limit."
								successLabel="JARM probes"
								failureLabel="Other probe failures"
								failureNote="The probe failed without reaching its deadline. A non-TLS port can never enter this table."
								latency={data.jarm}
							/>
						</div>

						<Panel
							title="Time spent per stage"
							note={`Successful attempts in ${periodLabel.toLowerCase()}. Each blue range is the interquartile range—the middle 50%—and the marker is the median. Minimum and maximum successful times are shown beneath it. Rows are scaled to their own timings, not to each other.`}
						>
							<div className="outcome-chart">
								{stages.map((stage) => (
									<TimingRow key={stage.label} label={stage.label} note={stage.note} timing={stage.timing} />
								))}
							</div>
						</Panel>
					</div>
				)}
			</section>

			<section className="analytics-section">
				<div className="section-title">
					<h2>Feeds</h2>
					<p>Current feed matches are unique addresses and are not weighted by scan frequency.</p>
				</div>

				<Panel
					title="Threat-list matches"
					note="Distinct addresses in each configured source, counted once however many ports the feed lists them on. JARM is derived from stored full-scan fingerprints; direct IP feeds do not require an open port."
				>
					{data.feeds.length ? (
						<ul className="feed-list">
							{data.feeds.map((feed) => (
								<li key={feed.source}>
									<div>
										<strong>{feed.source}</strong>
										{feed.local ? <span className="badge badge-local">your list</span> : null}
									</div>
									<output>{feed.hosts.toLocaleString()} matching addresses</output>
									<Meter value={feed.hosts / maxFeed} />
									{feed.local ? (
										<p>{feed.indicators.toLocaleString()} hashes configured · matches use JARM fingerprints collected by full scans</p>
									) : (
										<p>
											{feed.exclusive.toLocaleString()} of those addresses appear in no other configured threat list
											<span> · the full list names {feed.indicators.toLocaleString()} addresses</span>
										</p>
									)}
								</li>
							))}
						</ul>
					) : (
						<p className="panel-empty">No scanned addresses match a configured threat list.</p>
					)}
				</Panel>
			</section>
		</div>
	);
}
