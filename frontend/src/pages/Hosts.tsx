import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { acknowledge, dashboardPath } from "../api";
import { EmptyState } from "../components/EmptyState";
import { FilterDisclosure } from "../components/FilterDisclosure";
import { HostDetail } from "../components/HostDetail";
import { HostRow } from "../components/HostRow";
import { HostSummary } from "../components/HostSummary";
import { Pagination } from "../components/Pagination";
import { Search } from "../components/Search";
import { SelectAll } from "../components/SelectAll";
import { Table } from "../components/Table";
import { useFilters } from "../hooks/useFilters";
import { useResource } from "../hooks/useResource";
import { useSort } from "../hooks/useSort";
import { allowed, BANDS, DEFAULT_BANDS, FEED_ONLY_HOST_SORTS, HOST_SORTS, type Host, type HostsResponse, ORIGINS, selectedBands } from "../types";

export function Hosts({ feedOnly = false }: { feedOnly?: boolean }) {
	const [expanded, setExpanded] = useState<string | null>(null);
	const [params, set] = useFilters();
	const bands = selectedBands(params);
	const origin = allowed(params.get("origin"), ORIGINS);
	const port = params.get("port") ?? "";
	const sort = useSort(feedOnly ? FEED_ONLY_HOST_SORTS : HOST_SORTS);
	const bandMoved = String([...bands].sort()) !== String([...DEFAULT_BANDS].sort());
	const filterCount = Number(bandMoved) + (feedOnly ? 0 : Number(Boolean(origin)) + Number(Boolean(port)));
	// Named apart from the per-row acknowledgement pending set below.
	const {
		data,
		error,
		pending: updating,
		reload,
	} = useResource<HostsResponse>(dashboardPath("hosts", params, feedOnly), {
		poll: !expanded,
	});
	const [selected, setSelected] = useState<Set<string>>(new Set());
	const [pending, setPending] = useState<Set<string>>(new Set());
	const [failed, setFailed] = useState<Record<string, string>>({});
	const [bulkPending, setBulkPending] = useState<"ack" | "reset" | "">("");
	const [bulkError, setBulkError] = useState("");
	useEffect(() => {
		setExpanded(null);
		setSelected((current) => {
			const visible = (data?.hosts || []).filter((host) => current.has(host.ip));
			const acked = visible.length > 0 && visible[0].band === "ack";
			return new Set(visible.filter((host) => (host.band === "ack") === acked).map((host) => host.ip));
		});
	}, [data?.hosts]);

	const selectedHosts = useMemo(() => (data?.hosts || []).filter((host) => selected.has(host.ip)), [data?.hosts, selected]);
	const selectedAcked = selectedHosts.length > 0 && selectedHosts[0].band === "ack";
	const states = new Set((data?.hosts || []).map((host) => host.band === "ack"));
	const selectableState = selectedHosts.length ? selectedAcked : states.size === 1 ? [...states][0] : null;
	const selectable = selectableState === null ? [] : (data?.hosts || []).filter((host) => (host.band === "ack") === selectableState);
	const selectedCount = selectable.filter((host) => selected.has(host.ip)).length;

	const toggle = useCallback(function toggle(host: Host, checked: boolean) {
		setSelected((current) => {
			const next = new Set(current);
			if (checked) next.add(host.ip);
			else next.delete(host.ip);
			return next;
		});
	}, []);

	const toggleAll = useCallback(
		function toggleAll(checked: boolean) {
			setSelected((current) => {
				const next = new Set(current);
				selectable.forEach((host) => {
					if (checked) next.add(host.ip);
					else next.delete(host.ip);
				});
				return next;
			});
		},
		[selectable],
	);

	const ack = useCallback(
		async function ack(host: Host) {
			setPending((current) => new Set(current).add(host.ip));
			setFailed((current) => {
				const next = { ...current };
				delete next[host.ip];
				return next;
			});
			try {
				await acknowledge({ ip: host.ip }, feedOnly);
				toast.success(host.band === "ack" ? "Acknowledgement cleared" : "Host acknowledged");
				reload();
			} catch (caught) {
				const message = (caught as Error).message;
				setFailed((current) => ({ ...current, [host.ip]: message }));
				toast.error(`Could not update host: ${message}`);
			} finally {
				setPending((current) => {
					const next = new Set(current);
					next.delete(host.ip);
					return next;
				});
			}
		},
		[reload, feedOnly],
	);

	const bulkAck = useCallback(
		async function bulkAck(acked: boolean) {
			const ips = (data?.hosts || []).filter((host) => selected.has(host.ip)).map((host) => host.ip);
			if (!ips.length) return;
			setBulkPending(acked ? "ack" : "reset");
			setBulkError("");
			try {
				await acknowledge({ ips, acked }, feedOnly);
				setSelected(new Set());
				toast.success(`${ips.length} ${ips.length === 1 ? "host" : "hosts"} ${acked ? "acknowledged" : "reset"}`);
				reload();
			} catch (caught) {
				const message = `Bulk update failed: ${(caught as Error).message}`;
				setBulkError(message);
				toast.error(message);
			} finally {
				setBulkPending("");
			}
		},
		[data?.hosts, selected, reload, feedOnly],
	);

	if (!data) return <EmptyState>{error || "Loading..."}</EmptyState>;
	if (feedOnly && !data.configured) return <EmptyState>Set scan.feed_only_targets_file in Settings to enable feed-only matching.</EmptyState>;
	const count =
		data.matched === data.scanned ? `${data.scanned.toLocaleString()} hosts` : `${data.matched.toLocaleString()} of ${data.scanned.toLocaleString()} hosts`;

	return (
		<>
			<HostSummary data={data} feedOnly={feedOnly} />
			<Search
				className="hosts-bar"
				count={updating ? "Updating…" : bulkError || count}
				placeholder={feedOnly ? "Search address or reason" : "Search address, port, reason, fingerprint, certificate"}
			>
				{/* Filters and bulk actions share one wrapping line, so a narrow window drops the actions
          below the filters rather than running the two into each other. */}
				<div className="hosts-toolbar">
					<FilterDisclosure count={filterCount}>
						<fieldset className="checks bar-group">
							{/* The visible label cannot be the legend: a legend is not a flex item, so it would not
                sit on the row with the boxes. It is hidden and mirrored instead. */}
							<legend>Band</legend>
							<span className="bar-label" aria-hidden="true">
								Band
							</span>
							{BANDS.map((value) => (
								<label key={value}>
									<input
										type="checkbox"
										value={value}
										checked={bands.includes(value)}
										onChange={(event) => {
											// The empty string is the marker for "no bands", which is not the same as no filter.
											const next = event.target.checked ? [...bands.filter(Boolean), value] : bands.filter((band) => band !== value);
											set({ band: next.length ? next : [""] });
										}}
									/>
									{value === "ack" ? "Acknowledged" : value[0].toUpperCase() + value.slice(1)}
								</label>
							))}
						</fieldset>
						{!feedOnly && (
							<label className="bar-group">
								<span>Origin</span>
								<select value={origin} onChange={(event) => set({ origin: event.target.value })}>
									<option value="">All scans</option>
									<option value="manual">Manual</option>
									<option value="scheduled">Automatic</option>
								</select>
							</label>
						)}
						{!feedOnly && (
							<label className="bar-group">
								<span>Port</span>
								<input id="f-port" inputMode="numeric" placeholder="8443" value={port} onChange={(event) => set({ port: event.target.value.trim() })} />
							</label>
						)}
						{filterCount ? (
							<button type="button" className="ackbtn bar-clear" onClick={() => set({ band: [], origin: "", port: "" })}>
								CLEAR
							</button>
						) : null}
					</FilterDisclosure>
					<span className="bulk">
						<span className="selected-count" aria-live="polite">
							{selected.size} selected
						</span>
						<button
							type="button"
							className="ackbtn ack-action"
							disabled={!selected.size || selectedAcked || Boolean(bulkPending)}
							onClick={() => void bulkAck(true)}
						>
							{bulkPending === "ack" ? "ACKING…" : "ACK SELECTED"}
						</button>
						<button
							type="button"
							className="ackbtn reset-action"
							disabled={!selected.size || !selectedAcked || Boolean(bulkPending)}
							onClick={() => void bulkAck(false)}
						>
							{bulkPending === "reset" ? "RESETTING…" : "RESET SELECTED"}
						</button>
					</span>
				</div>
			</Search>
			<Table
				headers={
					feedOnly
						? ["", "Address", "Band", "Reason", "Last observed (UTC)", ""]
						: ["", "Address", "Open ports", "Band", "Reason", "Scanned by", "Last observed (UTC)", ""]
				}
				sort={{
					...sort,
					columns: {
						Address: "ip",
						...(feedOnly ? {} : { "Open ports": "ports" }),
						Band: "band",
						Reason: "reasons",
						"Last observed (UTC)": "recent",
					},
				}}
				firstHeader={
					<SelectAll
						checked={Boolean(selectable.length) && selectedCount === selectable.length}
						indeterminate={selectedCount > 0 && selectedCount < selectable.length}
						disabled={!selectable.length}
						tooltip={selectableState === null ? "Select an ACK state first" : `Select all ${selectableState ? "acknowledged" : "unacknowledged"} rows`}
						onChange={toggleAll}
					/>
				}
			>
				{data.hosts.map((host, index) => (
					<Fragment key={host.ip}>
						<HostRow
							host={host}
							index={index}
							selected={selected.has(host.ip)}
							incompatible={Boolean(selected.size) && (host.band === "ack") !== selectedAcked && !selected.has(host.ip)}
							pending={pending.has(host.ip)}
							failed={failed[host.ip] || ""}
							onToggle={toggle}
							onExpand={() => setExpanded(expanded === host.ip ? null : host.ip)}
							onAck={ack}
							feedOnly={feedOnly}
						/>
						<tr className="detail" id={`host-detail-${index}`} hidden={expanded !== host.ip}>
							<td colSpan={feedOnly ? 6 : 8}>
								<HostDetail host={host} feedOnly={feedOnly} />
							</td>
						</tr>
					</Fragment>
				))}
			</Table>
			{!data.hosts.length ? (
				<EmptyState>{data.scanned ? "No hosts match this filter." : "Nothing observed yet."}</EmptyState>
			) : (
				<Pagination page={data.page} pages={data.pages} />
			)}
		</>
	);
}
