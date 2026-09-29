import { dashboardPath } from "../api";
import { EmptyState } from "../components/EmptyState";
import { FilterDisclosure } from "../components/FilterDisclosure";
import { Search } from "../components/Search";
import { Table } from "../components/Table";
import { useFilters } from "../hooks/useFilters";
import { useResource } from "../hooks/useResource";
import { allowed, LOG_LEVELS, type LogEntry } from "../types";
import { stamp } from "../utils";

export function Logs() {
	const [params, set] = useFilters();
	const level = allowed(params.get("level"), LOG_LEVELS);
	const { data: entries, error } = useResource<LogEntry[]>(dashboardPath("log", params));
	if (!entries) return <EmptyState>{error || "Loading..."}</EmptyState>;
	return (
		<>
			<Search count={`${entries.length} ${entries.length === 1 ? "entry" : "entries"}`} placeholder="Search log messages">
				<FilterDisclosure count={level ? 1 : 0}>
					<label className="bar-group">
						<span>Level</span>
						<select value={level} onChange={(event) => set({ level: event.target.value })}>
							<option value="">Everything</option>
							<option value="ALERT">Alerts</option>
							<option value="ERROR">Errors</option>
							<option value="WARN">Warnings</option>
							<option value="INFO">Info</option>
							<option value="DEBUG">Debug</option>
						</select>
					</label>
				</FilterDisclosure>
			</Search>
			<Table headers={["Time (UTC)", "Level", "Message", "Detail"]}>
				{entries.map((entry, index) => (
					<tr key={`${entry.at}-${entry.level}-${entry.msg}-${entry.attrs}`} className={index % 2 ? "band" : undefined}>
						<td className="num muted">{stamp(entry.at)}</td>
						<td className={`lvl-${entry.level}`}>{entry.level}</td>
						<td>{entry.msg}</td>
						<td className="muted">{entry.attrs}</td>
					</tr>
				))}
			</Table>
			{!entries.length && <EmptyState>Nothing logged yet. The log is held in memory, so it starts empty after a restart.</EmptyState>}
		</>
	);
}
