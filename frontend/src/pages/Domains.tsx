import { Fragment } from "react";
import { dashboardPath } from "../api";
import { EmptyState } from "../components/EmptyState";
import { FilterDisclosure } from "../components/FilterDisclosure";
import { Search } from "../components/Search";
import { Table } from "../components/Table";
import { Tooltip } from "../components/Tooltip";
import { useFilters } from "../hooks/useFilters";
import { useResource } from "../hooks/useResource";
import { useSort } from "../hooks/useSort";
import { virusTotalDomain } from "../host-utils";
import { DOMAIN_SORTS, type DomainRow } from "../types";
import { copyText, stamp, today } from "../utils";

export function Domains() {
	const [params, set] = useFilters();
	const sort = useSort(DOMAIN_SORTS);
	const from = params.get("from") ?? "";
	const to = params.get("to") ?? "";
	const filtered = Number(Boolean(from)) + Number(Boolean(to));
	const { data: rows, error } = useResource<DomainRow[]>(dashboardPath("domains", params));
	if (!rows) return <EmptyState>{error || "Loading..."}</EmptyState>;
	const names = new Set(rows.flatMap((row) => row.names)).size;
	return (
		<>
			<Search
				placeholder="Search addresses, ports, domain names"
				count={`${names} ${names === 1 ? "domain" : "domains"} on ${rows.length} ${rows.length === 1 ? "endpoint" : "endpoints"}`}
			>
				<FilterDisclosure count={filtered}>
					{/* Either end alone is a valid filter, so the days bound each other rather than being
              required together: the picker itself is what stops an end before its start. */}
					<label className="bar-group">
						<span>From</span>
						<input type="date" value={from} max={to || undefined} onChange={(event) => set({ from: event.target.value })} />
					</label>
					<label className="bar-group">
						<span>To</span>
						<input type="date" value={to} min={from || undefined} onChange={(event) => set({ to: event.target.value })} />
					</label>
					<button type="button" className="ackbtn bar-clear" onClick={() => set({ from: today(), to: today() })}>
						TODAY
					</button>
					{filtered ? (
						<button type="button" className="ackbtn bar-clear" onClick={() => set({ from: "", to: "" })}>
							CLEAR
						</button>
					) : null}
				</FilterDisclosure>
			</Search>
			<Table
				headers={["Address", "Port", "Domain names", "Scanned at (UTC)"]}
				sort={{
					...sort,
					columns: { Address: "ip", Port: "port", "Domain names": "name", "Scanned at (UTC)": "recent" },
				}}
			>
				{rows.map((row, index) => (
					<tr key={`${row.ip}:${row.port}`} className={index % 2 ? "band" : undefined}>
						<td className="ip">
							<Tooltip content="Click to copy">
								<button type="button" className="rowbtn" aria-label={`Copy IP ${row.ip}`} onClick={() => void copyText(row.ip)}>
									{row.ip}
								</button>
							</Tooltip>
						</td>
						<td className="num">{row.port}</td>
						<td className="domains">
							{row.names.map((name, position) => {
								const href = virusTotalDomain(name);
								return (
									<Fragment key={name}>
										{position > 0 && ", "}
										{href ? (
											<Tooltip content="Look up on VirusTotal">
												<a className="namelink" href={href} target="_blank" rel="noopener noreferrer" aria-label={`Look up ${name} on VirusTotal`}>
													{name}
												</a>
											</Tooltip>
										) : (
											name
										)}
									</Fragment>
								);
							})}
						</td>
						<td className="num muted">{stamp(row.scanned_at)}</td>
					</tr>
				))}
			</Table>
			{!rows.length && <EmptyState>{params.get("q") || filtered ? "No domains match this filter." : "No certificate domain names collected yet."}</EmptyState>}
		</>
	);
}
