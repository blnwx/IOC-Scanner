import { useFilters } from "../hooks/useFilters";
import { type HostsResponse, selectedBands } from "../types";

export function HostSummary({ data, feedOnly = false }: { data: HostsResponse; feedOnly?: boolean }) {
	const [params, set] = useFilters();
	const bands = selectedBands(params);
	const tiles: [string, number, string?][] = [
		[feedOnly ? "Feed-only addresses" : "In scope", data.in_scope],
		["Observed hosts", data.scanned],
		...(!feedOnly ? ([["Live TLS", data.live_tls]] as [string, number][]) : []),
		["High", data.high, "high"],
		["Low", data.low, "low"],
		["Acknowledged", data.acked, "ack"],
	];
	return (
		<div className="tiles">
			{tiles.map(([label, value, band]) => {
				const content = (
					<>
						<output>{value.toLocaleString()}</output>
						<span>{label}</span>
					</>
				);
				if (!band)
					return (
						<div className="tile" key={label}>
							{content}
						</div>
					);
				const selected = bands.length === 1 && bands[0] === band;
				return (
					<button
						type="button"
						className={`tile tile-action ${band}`}
						key={label}
						aria-label={`${value.toLocaleString()} ${label}`}
						aria-pressed={selected}
						onClick={() => set({ band: selected ? [] : [band] })}
					>
						{content}
					</button>
				);
			})}
		</div>
	);
}
