import { Suspense } from "react";
import { Outlet, useLocation } from "react-router";
import { useNarrow } from "../hooks/useMedia";
import { EmptyState } from "./EmptyState";
import { Navigation } from "./Navigation";
import { ScanControls } from "./ScanControls";
import { Theme } from "./Theme";

export function DashboardLayout() {
	// The scan controls follow the host tables. Narrow screens drop them everywhere else.
	const onHosts = useLocation().pathname.startsWith("/hosts");
	const narrow = useNarrow();
	return (
		<>
			<aside className="edge">
				<div className="wordmark">IOC Scanner</div>
				<p className="tagline">Your own space, checked against the feeds.</p>
				<ScanControls hidden={narrow && !onHosts} />
				<Navigation narrow={narrow} />
				<section className="appearance">
					<h2>Appearance</h2>
					<Theme />
				</section>
			</aside>
			<main>
				<Suspense fallback={<EmptyState>Loading...</EmptyState>}>
					<Outlet />
				</Suspense>
			</main>
		</>
	);
}
