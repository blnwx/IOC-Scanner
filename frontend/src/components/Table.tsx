import type { PropsWithChildren, ReactNode } from "react";

export interface SortState {
	// The sort key the table is ordered by, "-" prefixed when descending.
	by: string;
	set: (by: string) => void;
	// Header label to the sort key the handler accepts. A label that is missing here is not sortable.
	columns: Record<string, string>;
}

interface SortHeaderProps {
	label: string;
	column: string;
	sorted: string;
	set: SortState["set"];
}

// Clicking cycles ascending, descending, then off, back to the table's own order.
function SortHeader({ label, column, sorted, set }: SortHeaderProps) {
	return (
		<button type="button" className="rowbtn" onClick={() => set(!sorted ? column : sorted === "ascending" ? `-${column}` : "")}>
			{label}
		</button>
	);
}

interface TableProps {
	headers: string[];
	actionClass?: string;
	firstHeader?: ReactNode;
	sort?: SortState;
}

export function Table({ headers, actionClass = "act", firstHeader, sort, children }: PropsWithChildren<TableProps>) {
	return (
		<div className="scroller">
			<table>
				<thead>
					<tr>
						{headers.map((label, index) => {
							// An unlabelled header is the select box in the first column or the row actions in the last.
							const column = sort?.columns[label];
							const sorted = !column ? "" : sort?.by === column ? "ascending" : sort?.by === `-${column}` ? "descending" : "";
							return (
								<th
									key={label || (index ? "actions" : "select")}
									className={sorted ? "sorted" : label ? undefined : index ? actionClass : "pick"}
									aria-label={!label && !index ? "Select rows" : undefined}
									aria-sort={sorted || undefined}
								>
									{!label && !index ? firstHeader : sort && column ? <SortHeader label={label} column={column} sorted={sorted} set={sort.set} /> : label}
								</th>
							);
						})}
					</tr>
				</thead>
				<tbody>{children}</tbody>
			</table>
		</div>
	);
}
