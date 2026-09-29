import type { MouseEvent } from "react";
import { sortSourcesByBand, sourceLinks } from "../host-utils";
import type { Host } from "../types";
import { copyText, stamp } from "../utils";
import { Badge } from "./Badge";
import { PortList } from "./PortList";
import { Tooltip } from "./Tooltip";

interface HostRowProps {
	host: Host;
	index: number;
	selected: boolean;
	incompatible: boolean;
	pending: boolean;
	failed: string;
	onToggle: (host: Host, checked: boolean) => void;
	onExpand: () => void;
	onAck: (host: Host) => Promise<void>;
	feedOnly?: boolean;
}

export function HostRow({ host, index, selected, incompatible, pending, failed, onToggle, onExpand, onAck, feedOnly = false }: HostRowProps) {
	function stop(event: MouseEvent) {
		event.stopPropagation();
	}
	function acknowledge(event: MouseEvent) {
		event.stopPropagation();
		void onAck(host);
	}
	function copyIP(event: MouseEvent) {
		event.stopPropagation();
		void copyText(host.ip);
	}
	const acked = host.band === "ack";
	const portRank: Record<string, number> = { high: 0, low: 1 };
	const shown = [...host.ports].sort((a, b) => (portRank[a.band] ?? 2) - (portRank[b.band] ?? 2) || a.port - b.port).slice(0, 10);
	return (
		<tr className={`row${index % 2 ? " band" : ""}${selected ? " selected" : ""}`} onClick={onExpand}>
			<td className="pick">
				<input
					type="checkbox"
					checked={selected}
					disabled={incompatible}
					onClick={stop}
					aria-label={`Select ${host.ip}`}
					onChange={(event) => onToggle(host, event.target.checked)}
				/>
			</td>
			<td className="ip">
				<Tooltip content="Click to copy">
					<button type="button" className="rowbtn" aria-label={`Copy IP ${host.ip}`} onClick={copyIP}>
						{host.ip}
					</button>
				</Tooltip>
			</td>
			{!feedOnly && (
				<td className="num">
					<PortList ports={shown} count={host.port_count} />
				</td>
			)}
			<td className={`band-${host.band || "clean"}`}>
				<span className="mark" />
				{host.band ? host.band.toUpperCase() : "clean"}
			</td>
			{host.signals.length ? (
				<td className="reason">
					{sortSourcesByBand([...new Set(host.signals.map((signal) => signal.source))]).map((source) => {
						// One badge stands for every signal from this source, so show the worst score.
						const scores = host.signals.flatMap((signal) => (signal.source === source && signal.confidence_level != null ? [signal.confidence_level] : []));
						return <Badge key={source} source={source} links={sourceLinks(host, source)} score={scores.length ? Math.max(...scores) : undefined} />;
					})}
				</td>
			) : (
				<td className="reason muted">nothing fired</td>
			)}
			{!feedOnly && <td className="muted">{host.manual ? "Manual" : "Automatic"}</td>}
			<td className="num muted">{stamp(host.checked_at)}</td>
			<td className="num act">
				<Tooltip
					direction="left"
					content={
						failed
							? `Could not save that: ${failed}`
							: acked
								? "Put this host back in the queue"
								: "Mark as dealt with: destroyed, cleaned up, or read and cleared"
					}
				>
					<button
						type="button"
						className={`ackbtn ${acked ? "reset-action" : "ack-action"}`}
						disabled={pending}
						aria-label={`${acked ? "Clear the acknowledgement on " : "Acknowledge "}${host.ip}`}
						onClick={acknowledge}
					>
						{failed ? "RETRY" : acked ? "RESET" : "ACK"}
					</button>
				</Tooltip>
			</td>
		</tr>
	);
}
