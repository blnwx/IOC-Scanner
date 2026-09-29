import { EmptyState } from "../components/EmptyState";
import { TargetEditor } from "../components/TargetEditor";
import { useResource } from "../hooks/useResource";
import type { TargetsResponse } from "../types";

export function Targets() {
	const { data, error } = useResource<TargetsResponse>("/api/targets", {
		poll: false,
		store: false,
	});
	const {
		data: feedOnly,
		error: feedOnlyError,
		reload: reloadFeedOnly,
	} = useResource<TargetsResponse>("/api/targets?target=feed-only", {
		poll: false,
		store: false,
	});
	if (!data || !feedOnly) return <EmptyState>{error || feedOnlyError || "Loading..."}</EmptyState>;
	return (
		<>
			<section className="group">
				<h2>Active</h2>
				<TargetEditor data={data} onSaved={reloadFeedOnly} />
			</section>
			<section className="group">
				<h2>Feed-only</h2>
				{feedOnly.targets_file ? (
					<TargetEditor data={feedOnly} feedOnly />
				) : (
					<EmptyState>Set scan.feed_only_targets_file in Settings to enable feed-only matching.</EmptyState>
				)}
			</section>
		</>
	);
}
