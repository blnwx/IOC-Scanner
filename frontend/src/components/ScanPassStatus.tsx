export interface ScanPassStatusProps {
	name: "scheduled" | "manual";
	state: string;
	detail: string;
	busy: boolean;
}

export function ScanPassStatus({ name, state, detail, busy }: ScanPassStatusProps) {
	return (
		<p className={`scan-state${busy ? " busy" : ""}`} role="status" aria-label={`${name === "scheduled" ? "Scheduled" : "Manual"} scan status`}>
			<span className="dot" aria-hidden="true" />
			<span className="scan-status">{state}</span>
			<span className="scan-detail">{detail}</span>
		</p>
	);
}
