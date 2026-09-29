import type { AnalyticsResponse } from "../types";
import { copyText } from "../utils";
import { Panel } from "./Panel";

const portLimit = 12;

// Zero of zero is 0%, not NaN: a period with no full scans yet still has to render the panel.
function share(part: number, whole: number): string {
	return `${whole ? Math.round((part / whole) * 100) : 0}%`;
}

export function PortCoverage({ coverage }: { coverage: AnalyticsResponse["coverage"] }) {
	const ratedPorts = coverage.ports.filter((row) => row.high + row.low > 0);
	const suggestedPorts = (ratedPorts.length ? ratedPorts : coverage.ports.filter((row) => row.configured)).slice(0, portLimit);
	const suggestedSet = new Set(suggestedPorts.map((row) => row.port));
	const replacements = suggestedPorts.filter((row) => !row.configured);
	const removals = coverage.ports.filter((row) => row.configured && !suggestedSet.has(row.port));
	const suggestedList = suggestedPorts.map((row) => row.port).join(" ");
	const suggestedConfig = `common_ports = [${suggestedPorts.map((row) => row.port).join(", ")}]`;
	const visiblePorts = [...removals, ...suggestedPorts].slice(0, portLimit);

	return (
		<section className="analytics-section priority-section">
			<div className="section-title">
				<h2>Ports</h2>
				<p>Unique endpoints observed by full 1-65,535 scans only. Repeated common scans never affect these rankings.</p>
			</div>

			<Panel
				title="Common-port scan coverage"
				note={`The common range is scanned first to find likely C2 ports quickly. Ports outside common_ports are not missed: they are scanned later in the full 1-65,535 scan, which may take hours for a large target list. The table compares the current config with the ${portLimit} highest-ranked relevant ports.`}
			>
				<div className="coverage-score">
					<output>{share(coverage.flagged_covered, coverage.flagged)}</output>
					<div>
						<strong>of rated endpoints are prioritized</strong>
						<span>
							{coverage.flagged_covered.toLocaleString()} of {coverage.flagged.toLocaleString()} HIGH or LOW endpoints sit on a port scanned in the common range
						</span>
					</div>
				</div>
				<div className="coverage-config">
					<div>
						<strong>Suggested full config</strong>
						<span>Paste under [scan]</span>
					</div>
					<code>{suggestedConfig}</code>
					<button type="button" className="ackbtn" aria-label="Copy suggested ports" onClick={() => void copyText(suggestedList)}>
						COPY
					</button>
					<button type="button" className="ackbtn" aria-label="Copy suggested ports as TOML" onClick={() => void copyText(suggestedConfig)}>
						COPY TOML
					</button>
				</div>
				{visiblePorts.length ? (
					<div className="scroller">
						<table className="coverage-table">
							<thead>
								<tr>
									<th>Port</th>
									<th>Endpoints</th>
									<th>High</th>
									<th>Low</th>
									<th>Common scan</th>
								</tr>
							</thead>
							<tbody>
								{visiblePorts.map((row) => {
									const rated = row.high + row.low;
									const removalIndex = removals.indexOf(row);
									const removal = removalIndex >= 0;
									const replacement = replacements[removalIndex];
									const suggestion = replacement
										? `replace with ${replacement.port} (${replacement.high.toLocaleString()} HIGH, ${replacement.low.toLocaleString()} LOW)`
										: "consider removing";
									const removalReason = rated ? "below recommendation cutoff" : row.hosts ? "no rated hits" : "nothing listening";
									return (
										<tr key={row.port} className={removal ? "remove-candidate" : !row.configured ? "later-finding" : undefined}>
											<th scope="row" className="num">
												{row.port}
											</th>
											<td className={row.hosts ? "num" : "num muted"}>{row.hosts.toLocaleString()}</td>
											<td className={row.high ? "num band-high" : "num muted"}>{row.high.toLocaleString()}</td>
											<td className={row.low ? "num band-low" : "num muted"}>{row.low.toLocaleString()}</td>
											<td className="verdict">
												{removal ? `${removalReason} — ${suggestion}` : row.configured ? "scanned first" : "scanned later — consider adding"}
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				) : (
					<p className="panel-empty">No full-scan results yet.</p>
				)}
			</Panel>
		</section>
	);
}
