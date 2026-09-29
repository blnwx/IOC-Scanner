import type { ReactNode } from "react";

export function DetailEntry({ label, value }: { label: string; value: ReactNode }) {
	return (
		<>
			<dt>{label}</dt>
			<dd>{value || "—"}</dd>
		</>
	);
}
