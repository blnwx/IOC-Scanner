import { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router";

// The nav lists routes, not views: feed-only hosts is a page of its own. Ordered as the menu reads.
const LINKS: [path: string, label: string][] = [
	["/hosts", "Hosts"],
	["/hosts/feed-only", "Feed-only hosts"],
	["/domains", "Domains"],
	["/analytics", "Analytics"],
	["/jarm", "JARM"],
	["/jarm-blacklist", "JARM Blacklist"],
	["/log", "Log"],
	["/settings", "Settings"],
	["/targets", "Targets"],
];

export function Navigation({ narrow }: { narrow: boolean }) {
	const { pathname } = useLocation();
	const [open, setOpen] = useState(!narrow);
	useEffect(() => setOpen(!narrow), [narrow]);
	// Longest match wins, so /hosts/feed-only names itself rather than its parent. The collapsed
	// menu on a phone is the only place this shows: it says which page is open.
	const current = LINKS.filter(([path]) => pathname === path || pathname.startsWith(`${path}/`)).at(-1)?.[1] ?? "Hosts";

	function close() {
		if (narrow) setOpen(false);
	}

	return (
		<section className="view-section">
			<h2 className="view-heading">View</h2>
			<details id="view-menu" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
				<summary>
					<span>View</span>
					<span>{current}</span>
				</summary>
				<nav>
					{LINKS.map(([path, label]) => (
						// Every entry is an exact page, so none of them stays current on a deeper route.
						<NavLink key={path} to={path} end onClick={close}>
							{label}
						</NavLink>
					))}
				</nav>
			</details>
		</section>
	);
}
