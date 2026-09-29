import { type PropsWithChildren, type ReactNode, useEffect, useRef, useState } from "react";
import { useFilters } from "../hooks/useFilters";

interface SearchProps {
	className?: string;
	count: ReactNode;
	placeholder: string;
}

export function Search({ className, count, placeholder, children }: PropsWithChildren<SearchProps>) {
	const [params, set] = useFilters();
	const query = params.get("q") ?? "";
	const [draft, setDraft] = useState(query);
	const outgoing = useRef<string | null>(null);
	const timer = useRef(0);
	useEffect(() => {
		timer.current = window.setTimeout(() => {
			const next = draft.trim();
			if (next !== query) {
				outgoing.current = next;
				set({ q: next });
			}
		}, 200);
		return () => window.clearTimeout(timer.current);
	}, [draft, query, set]);
	// The box follows the URL, so back and forward move the text. Two things stop that from fighting
	// the typist: the navigation this box started is recognised and ignored, because more characters
	// may have arrived while it was in flight; and the timer the effect above re-arms on the same
	// render is cleared, so it cannot fire with the draft this one just replaced.
	useEffect(() => {
		if (outgoing.current !== null && outgoing.current === query) {
			outgoing.current = null;
			return;
		}
		window.clearTimeout(timer.current);
		setDraft(query);
	}, [query]);
	return (
		<div className={`bar${className ? ` ${className}` : ""}`}>
			<input type="search" autoComplete="off" aria-label="Search" placeholder={placeholder} value={draft} onChange={(event) => setDraft(event.target.value)} />
			<span className="count">{count}</span>
			{children}
		</div>
	);
}
