import { useEffect, useState } from "react";

export function Theme() {
	const media = typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : null;
	function current() {
		return window.localStorage.getItem("theme") ? document.documentElement.style.colorScheme === "dark" : Boolean(media?.matches);
	}
	const [dark, setDark] = useState(current);
	useEffect(() => {
		if (!media) return;
		const update = (event: MediaQueryListEvent) => {
			if (!window.localStorage.getItem("theme")) setDark(event.matches);
		};
		media.addEventListener("change", update);
		return () => media.removeEventListener("change", update);
	}, [media]);

	function toggle() {
		const scheme = dark ? "light" : "dark";
		document.documentElement.style.colorScheme = scheme;
		window.localStorage.setItem("theme", scheme);
		setDark(!dark);
	}

	return (
		<button type="button" className="theme" aria-pressed={dark} onClick={toggle}>
			{dark ? "Light mode" : "Dark mode"}
		</button>
	);
}
