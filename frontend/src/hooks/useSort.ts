import { useCallback } from "react";
import { useFilters } from "./useFilters";

// Reads the ordering a table is showing out of the URL, ready to hand to <Table sort>: the sort key
// the handler accepts, "-" prefixed when descending. A key the table does not offer is ignored, so a
// hand-typed URL paints the table's own order rather than a header arrow pointing at nothing.
export function useSort(sorts: readonly string[]) {
	const [params, set] = useFilters();
	const requested = params.get("sort") ?? "";
	const by = sorts.includes(requested.replace(/^-/, "")) ? requested : "";
	const change = useCallback((next: string) => set({ sort: next }), [set]);
	return { by, set: change };
}
