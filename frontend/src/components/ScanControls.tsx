import { useState } from "react";
import { useScan } from "../context/ScanContext";
import { scanPassText } from "../scan-utils";
import { ScanPassStatus } from "./ScanPassStatus";

export function ScanControls({ hidden }: { hidden: boolean }) {
	const [targets, setTargets] = useState("");
	const { status, pending, refused, now, start } = useScan();

	const scheduled = scanPassText("scheduled", status.scheduled, now);
	const manual = refused
		? { state: "Scan refused", detail: refused, busy: false }
		: pending
			? { state: "Asking for a manual scan…", detail: "", busy: true }
			: scanPassText("manual", status.manual, now);
	const busy = pending || (!refused && (status.manual.queued || status.manual.running));
	const disabled = busy || !targets?.trim();

	return (
		<section className="scan-section" hidden={hidden}>
			<h2 className="scan-heading">Scan</h2>
			<div className="scan">
				<ScanPassStatus name="scheduled" {...scheduled} />
				<ScanPassStatus name="manual" {...manual} />
			</div>
			<form className="scan-actions" onSubmit={(event) => event.preventDefault()}>
				<label htmlFor="scan-targets">Targets</label>
				<input
					id="scan-targets"
					type="text"
					placeholder="192.0.2.5, 198.51.100.0/28, AS13335"
					aria-label="Targets: IPs, CIDRs, or ASNs"
					autoComplete="off"
					spellCheck={false}
					disabled={busy}
					required
					value={targets}
					onChange={(event) => setTargets(event.target.value)}
				/>
				<button type="button" className="run" disabled={disabled} onClick={() => void start("common", targets.trim())}>
					Scan common ports
				</button>
				<button type="button" className="run" disabled={disabled} onClick={() => void start("full", targets.trim())}>
					Scan all ports
				</button>
			</form>
		</section>
	);
}
