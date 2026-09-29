import { type ReactNode, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface TooltipProps {
	content: string;
	children: ReactNode;
	direction?: "top" | "bottom" | "left" | "right";
}

export function Tooltip({ content, children, direction = "top" }: TooltipProps) {
	const id = useId();
	const trigger = useRef<HTMLSpanElement>(null);
	const [position, setPosition] = useState<{
		left: number;
		top: number;
	} | null>(null);
	function show() {
		const rect = trigger.current?.getBoundingClientRect();
		if (!rect) return;
		const left = rect.left + window.scrollX;
		const top = rect.top + window.scrollY;
		if (direction === "left") setPosition({ left: left - 6, top: top + rect.height / 2 });
		else if (direction === "right") setPosition({ left: left + rect.width + 6, top: top + rect.height / 2 });
		else if (direction === "bottom") setPosition({ left: left + rect.width / 2, top: top + rect.height + 6 });
		else setPosition({ left: left + rect.width / 2, top: top - 6 });
	}
	function hide() {
		setPosition(null);
	}

	return (
		<>
			{/* biome-ignore lint/a11y/noStaticElementInteractions: the wrapper must receive hover when its control is disabled */}
			<span ref={trigger} className="tooltip" aria-describedby={position ? id : undefined} onBlur={hide} onFocus={show} onMouseEnter={show} onMouseLeave={hide}>
				{children}
			</span>
			{position &&
				createPortal(
					<span id={id} role="tooltip" className={`tooltip-popup tooltip-${direction}`} style={position}>
						{content}
					</span>,
					document.body,
				)}
		</>
	);
}
