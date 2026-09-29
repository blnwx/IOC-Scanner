import { useState } from "react";
import { dashboardPath } from "../api";
import { EmptyState } from "../components/EmptyState";
import { JarmTableRow } from "../components/JarmTableRow";
import { Search } from "../components/Search";
import { Table } from "../components/Table";
import { useFilters } from "../hooks/useFilters";
import { useResource } from "../hooks/useResource";
import { useSort } from "../hooks/useSort";
import { JARM_SORTS, type JarmRow } from "../types";

export function Jarm() {
	const [editing, setEditing] = useState("");
	const [params] = useFilters();
	const sort = useSort(JARM_SORTS);
	const { data: rows, error, reload } = useResource<JarmRow[]>(dashboardPath("jarm", params), { poll: !editing });
	if (!rows) return <EmptyState>{error || "Loading..."}</EmptyState>;
	return (
		<>
			<Search count={`${rows.length} ${rows.length === 1 ? "hash" : "hashes"}`} placeholder="Search JARM hashes" />
			<Table
				headers={["Hash", "Lifetime hosts", "First seen (UTC)", "Last seen (UTC)", ""]}
				sort={{
					...sort,
					columns: {
						Hash: "hash",
						"Lifetime hosts": "hosts",
						"First seen (UTC)": "first",
						"Last seen (UTC)": "recent",
					},
				}}
			>
				{rows.map((row, index) => (
					<JarmTableRow
						key={row.hash}
						row={row}
						banded={Boolean(index % 2)}
						editing={editing === row.hash}
						onEdit={() => setEditing(row.hash)}
						onClose={() => setEditing("")}
						onSaved={reload}
					/>
				))}
			</Table>
			{!rows.length && <EmptyState>{params.get("q") ? "No JARM hashes match this search." : "No JARM sightings yet."}</EmptyState>}
		</>
	);
}
