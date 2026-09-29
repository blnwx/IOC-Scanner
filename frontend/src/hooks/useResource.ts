import { useCallback, useEffect, useRef, useState } from "react";
import { getJSON } from "../api";

// One response per endpoint: the last one loaded, so returning to a view repaints instantly.
// Older responses are not kept. Every response carries totals for the whole database rather than
// the page, so painting an older one would wind the summary figures back to numbers the user has
// already watched change.
const cache = new Map<string, { path: string; value: unknown }>();

// Everything before the query string. One hosts response supersedes every other hosts response,
// whatever filter asked for it.
function endpoint(path: string) {
	return path.split("?")[0];
}

export function resetResourceCache() {
	cache.clear();
}

export function useResource<T>(
	path: string,
	options?: { poll?: boolean; store?: boolean },
): {
	data: T | null;
	error: string;
	pending: boolean;
	reload: () => void;
} {
	const poll = options?.poll ?? true;
	const store = options?.store ?? true;
	// The path is kept with the response so the rows on screen can be told apart from the rows
	// being asked for.
	const [loaded, setLoaded] = useState<{ path: string; value: T } | null>(null);
	const [error, setError] = useState("");
	const request = useRef<AbortController | null>(null);
	const cached = store ? (cache.get(endpoint(path)) as { path: string; value: T } | undefined) : undefined;
	// A cached response for this exact path, or else whatever was loaded last: its rows belong to
	// the previous filter for the width of one request, but its totals are the current ones.
	const shown = cached?.path === path ? cached : loaded;
	const data = shown?.value ?? null;

	const load = useCallback(async () => {
		request.current?.abort();
		const controller = new AbortController();
		request.current = controller;
		setError("");
		try {
			const next = await getJSON<T>(path, controller.signal);
			if (controller.signal.aborted) return;
			if (store) cache.set(endpoint(path), { path, value: next });
			setLoaded({ path, value: next });
		} catch (caught) {
			if (controller.signal.aborted || (store && cache.has(endpoint(path)))) return;
			setError(`Cannot reach the scanner: ${(caught as Error).message}`);
			setLoaded(null);
		}
	}, [path, store]);

	useEffect(() => {
		void load();
		return () => request.current?.abort();
	}, [load]);

	useEffect(() => {
		if (!poll) return;
		function refresh() {
			if (!document.hidden) void load();
		}
		const timer = window.setInterval(refresh, 10_000);
		document.addEventListener("visibilitychange", refresh);
		return () => {
			window.clearInterval(timer);
			document.removeEventListener("visibilitychange", refresh);
		};
	}, [load, poll]);

	const reload = useCallback(() => void load(), [load]);
	// A failure only reaches the page when there is nothing to show. Moving to a path that is already
	// cached would otherwise paint the previous path's error over good data until the reload lands.
	//
	// Pending means the rows on screen answer a different question to the one now being asked, which
	// is the only case the reader cannot see for themselves: the view looks settled but is not. A
	// background poll re-fetches the same path and is deliberately not pending, or the count would
	// stir every ten seconds for nothing.
	return { data, error: data ? "" : error, pending: Boolean(shown) && shown?.path !== path, reload };
}
