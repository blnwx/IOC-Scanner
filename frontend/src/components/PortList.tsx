import { Fragment } from "react";
import { reasonText } from "../host-utils";
import type { Port } from "../types";
import { Tooltip } from "./Tooltip";

export function PortList({ ports, count }: { ports: Port[]; count: number }) {
	return (
		<>
			{ports.map((port, index) => (
				<Fragment key={port.port}>
					{index > 0 && " "}
					{port.band ? (
						<Tooltip content={(port.signals || []).map(reasonText).join("\n") || "Named by a feed"}>
							<span className={`port-flag ${port.band}`}>{port.port}</span>
						</Tooltip>
					) : (
						<span className="port-clean">{port.port}</span>
					)}
				</Fragment>
			))}
			{!count ? <span className="muted">—</span> : count > ports.length ? <span className="muted"> +{count - ports.length} more</span> : null}
		</>
	);
}
