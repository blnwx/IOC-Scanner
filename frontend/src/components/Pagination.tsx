import { useFilters } from "../hooks/useFilters";
import { allowed, DEFAULT_SIZE, PAGE_SIZES } from "../types";

export function Pagination({ page, pages }: { page: number; pages: number }) {
	const [params, set] = useFilters();
	const size = allowed(params.get("size"), PAGE_SIZES, DEFAULT_SIZE);
	// The first page and the default size are what the bare URL already means, so neither is written.
	return (
		<div className="pager">
			<button type="button" disabled={page <= 1} onClick={() => set({ page: page <= 2 ? "" : String(page - 1) })}>
				Previous
			</button>
			<span className="num">
				Page {page} of {pages}
			</span>
			<button type="button" disabled={page >= pages} onClick={() => set({ page: String(page + 1) })}>
				Next
			</button>
			<label>
				Rows{" "}
				<select
					aria-label="Rows per page"
					value={size}
					onChange={(event) =>
						set({
							size: event.target.value === DEFAULT_SIZE ? "" : event.target.value,
						})
					}
				>
					{PAGE_SIZES.map((value) => (
						<option key={value}>{value}</option>
					))}
				</select>
			</label>
		</div>
	);
}
