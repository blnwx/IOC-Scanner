import { detailLink, feedDate } from "../host-utils";
import type { Indicator } from "../types";
import { Badge } from "./Badge";

interface SignalReasonProps {
	signal: Indicator;
	ip: string;
	trailing?: string;
	// Under a certificate the value is usually the heading's own ip:port or its fingerprint, so it
	// is shown only for the feeds that match on a domain instead. A host-level hit has no such
	// heading to read it from, and always shows it.
	showValue?: boolean;
}

// One layout for every feed hit, wherever it appears: badge, tag, value, date.
export function SignalReason({ signal, ip, trailing = "", showValue = false }: SignalReasonProps) {
	return (
		<div>
			<Badge source={signal.source} links={[detailLink(signal, ip)]} score={signal.confidence_level} />
			{signal.tag}
			{showValue || ["phishing_army", "threatview"].includes(signal.source) ? ` — ${signal.value}` : ""}
			{feedDate(signal)}
			{trailing}
		</div>
	);
}
