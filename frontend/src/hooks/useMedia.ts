import { useEffect, useState } from "react";

export function useMedia(query: string): boolean {
	function getMatch() {
		return typeof matchMedia === "function" && matchMedia(query).matches;
	}

	const [matches, setMatches] = useState(getMatch);
	useEffect(() => {
		if (typeof matchMedia !== "function") return;
		const media = matchMedia(query);
		const update = () => setMatches(media.matches);
		update();
		media.addEventListener("change", update);
		return () => media.removeEventListener("change", update);
	}, [query]);
	return matches;
}

// The one width the layout switches at, matching the media query in app.css.
export function useNarrow(): boolean {
	return useMedia("(max-width: 820px)");
}
