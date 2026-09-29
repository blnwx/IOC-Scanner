import { useLayoutEffect, useRef } from "react";
import type { Latency } from "../types";
import { duration } from "./LatencyChart";

// spreadLabels centres each caption on its own mark, then resolves overlap by cascading away from
// anchorIndex: that caption keeps its ideal position (clamped only to the track edges), and every
// other caption is pushed off the one already placed between it and the anchor. Anchors must arrive
// in ascending order. Returns left offsets in pixels.
export function spreadLabels(anchors: number[], sizes: number[], width: number, gap = 8, anchorIndex = 0): number[] {
	const ideal = anchors.map((at, i) => (at / 100) * width - sizes[i] / 2);
	const clamp = (i: number, left: number) => Math.max(0, Math.min(left, width - sizes[i]));
	const lefts = ideal.slice();
	lefts[anchorIndex] = clamp(anchorIndex, lefts[anchorIndex]);
	for (let i = anchorIndex + 1; i < lefts.length; i += 1) lefts[i] = Math.max(ideal[i], lefts[i - 1] + sizes[i - 1] + gap);
	for (let i = anchorIndex - 1; i >= 0; i -= 1) lefts[i] = Math.min(ideal[i], lefts[i + 1] - sizes[i] - gap);
	return lefts.map((left, i) => clamp(i, left));
}

// IQRLabels positions each caption under the mark it names. Widths have to be measured, so this
// cannot be CSS: the captions are variable-length text and the quartiles can sit a pixel apart.
// The median caption keeps its exact mark; the quartile captions are the ones that give way.
function IQRLabels({ marks }: { marks: { label: string; value: string; at: number }[] }) {
	const row = useRef<HTMLDivElement>(null);
	const anchors = marks.map((mark) => mark.at).join(",");
	const anchorIndex = Math.max(
		0,
		marks.findIndex((mark) => mark.label === "Median"),
	);
	useLayoutEffect(() => {
		const node = row.current;
		if (!node) return;
		const place = () => {
			const captions = [...node.children] as HTMLElement[];
			const width = node.clientWidth;
			// Zero width is a stacked phone layout or a hidden panel; both position themselves.
			if (!width) return;
			const lefts = spreadLabels(
				anchors.split(",").map(Number),
				captions.map((caption) => caption.offsetWidth),
				width,
				8,
				anchorIndex,
			);
			captions.forEach((caption, i) => {
				caption.style.left = `${lefts[i]}px`;
			});
		};
		place();
		window.addEventListener("resize", place);
		return () => window.removeEventListener("resize", place);
	}, [anchors, anchorIndex]);

	return (
		<div className="iqr-labels" ref={row}>
			{marks.map((mark) => (
				<span key={mark.label} style={{ left: `${mark.at}%` }}>
					{mark.label} <strong>{mark.value}</strong>
				</span>
			))}
		</div>
	);
}

interface TimingRowProps {
	label: string;
	note: string;
	timing: Latency;
}

// Each row is scaled to its own timing. A complete probe is ten JARM dials plus the handshake, so
// one shared scale would leave the three stages inside it as a sliver against the left edge.
export function TimingRow({ label, note, timing }: TimingRowProps) {
	if (!timing.successes)
		return (
			<div className="outcome-row">
				<div className="outcome-title">
					<div>
						<strong>{label}</strong>
						<span>{note}</span>
					</div>
					<output>—</output>
				</div>
				<p className="panel-empty">No completed attempts recorded yet.</p>
			</div>
		);
	const maximum = timing.q3_us * 1.25 || 1;
	const at = (value: number) => Math.min(100, (value / maximum) * 100);
	const position = (value: number) => `${at(value)}%`;
	const marks = [
		{
			label: "Lower quartile",
			value: duration(timing.q1_us),
			at: at(timing.q1_us),
		},
		{
			label: "Median",
			value: duration(timing.median_us),
			at: at(timing.median_us),
		},
		{
			label: "Upper quartile",
			value: duration(timing.q3_us),
			at: at(timing.q3_us),
		},
	];
	return (
		<div className="outcome-row">
			<div className="outcome-title">
				<div>
					<strong>{label}</strong>
					<span>{note}</span>
				</div>
				<output>{timing.successes.toLocaleString()} measured</output>
			</div>
			<div
				className="iqr-track"
				role="img"
				aria-label={`${label}: minimum ${duration(timing.min_us)}, lower quartile ${duration(timing.q1_us)}, median ${duration(timing.median_us)}, upper quartile ${duration(timing.q3_us)}, maximum ${duration(timing.max_us)}`}
			>
				<span
					className="iqr-band"
					style={{
						left: position(timing.q1_us),
						width: position(timing.q3_us - timing.q1_us),
					}}
				/>
				<span className="median-marker" style={{ left: position(timing.median_us) }} />
			</div>
			<div className="range-labels">
				<span>
					Minimum <strong>{duration(timing.min_us)}</strong>
				</span>
				<span>
					Maximum <strong>{duration(timing.max_us)}</strong>
				</span>
			</div>
			<IQRLabels marks={marks} />
		</div>
	);
}
