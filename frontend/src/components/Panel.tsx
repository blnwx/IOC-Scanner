import type { PropsWithChildren, ReactNode } from "react";

interface PanelProps {
	title: string;
	note?: ReactNode;
	wide?: boolean;
}

// Panel is one figure on the analytics grid: a hairline box, the table's own 10px uppercase
// heading, and an optional note under it saying what the figures are counted over.
export function Panel({ title, note, wide, children }: PropsWithChildren<PanelProps>) {
	return (
		<section className={wide ? "panel wide" : "panel"}>
			<h3>{title}</h3>
			{note ? <p className="panel-note">{note}</p> : null}
			{children}
		</section>
	);
}
