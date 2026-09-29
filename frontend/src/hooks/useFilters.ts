import { useCallback } from "react";
import { useSearchParams } from "react-router";

type FilterPatch = Record<string, string | string[]>;

export function useFilters() {
	const [params, setParams] = useSearchParams();
	const set = useCallback(
		(patch: FilterPatch) => {
			setParams((previous) => {
				const next = new URLSearchParams(previous);
				for (const [key, value] of Object.entries(patch)) {
					next.delete(key);
					if (Array.isArray(value)) {
						for (const item of value) next.append(key, item);
					} else if (value) {
						next.set(key, value);
					}
				}
				if (!("page" in patch)) next.delete("page");
				return next;
			});
		},
		[setParams],
	);
	return [params, set] as const;
}
