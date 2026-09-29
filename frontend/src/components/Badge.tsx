import type { MouseEvent } from "react";
import { tierOf } from "../host-utils";
import { Tooltip } from "./Tooltip";

export function Badge({ source, links = [], score }: { source: string; links?: string[]; score?: number }) {
	const unique = [...new Set(links.filter(Boolean))];
	const className = `badge badge-${tierOf(source)}`;
	// Only ThreatFox scores anything, so the data itself decides whether this renders.
	const confidence =
		score == null ? null : (
			<Tooltip content="Confidence level">
				<span className={`confidence band-${score > 50 ? "high" : "low"}`}>{score}%</span>
			</Tooltip>
		);
	if (!unique.length)
		return (
			<>
				<span className={className}>{source}</span>
				{confidence}
			</>
		);

	function open(event: MouseEvent<HTMLAnchorElement>) {
		event.stopPropagation();
		if (unique.length === 1) return;
		event.preventDefault();
		unique.forEach((link) => {
			window.open(link, "_blank", "noopener,noreferrer");
		});
	}

	return (
		<>
			<Tooltip content="Open feed source">
				<a className={className} href={unique[0]} target="_blank" rel="noopener noreferrer" onClick={open}>
					{source}
				</a>
			</Tooltip>
			{confidence}
		</>
	);
}
