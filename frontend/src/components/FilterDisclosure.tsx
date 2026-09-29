import { type PropsWithChildren, useEffect, useState } from "react";
import { useNarrow } from "../hooks/useMedia";

// The filters sit in the page toolbar beside the search box. Narrow, there is no room for them, so
// they collapse behind a disclosure; widening always opens them again. The count is of the filters
// actually narrowing the table — collapsed, the menu otherwise hides the reason the results look
// short. Empty at zero, so :empty does the hiding.
export function FilterDisclosure({ count, children }: PropsWithChildren<{ count: number }>) {
	const narrow = useNarrow();
	const [open, setOpen] = useState(!narrow);
	useEffect(() => setOpen(!narrow), [narrow]);
	return (
		<details className="filter-disclosure" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
			<summary>
				<span>Filters</span>
				<span className="filter-count">{count || ""}</span>
			</summary>
			<div className="filter-controls">{children}</div>
		</details>
	);
}
