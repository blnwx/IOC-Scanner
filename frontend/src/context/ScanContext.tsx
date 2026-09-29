import { createContext, type PropsWithChildren, useCallback, useContext, useEffect, useState } from "react";
import { toast } from "sonner";
import { getScan, startScan } from "../api";
import { EMPTY_PASS } from "../scan-utils";
import type { ScanStatus } from "../types";

interface ScanContextValue {
	status: ScanStatus;
	pending: boolean;
	refused: string;
	now: number;
	start: (kind: "common" | "full", targets: string) => Promise<void>;
}

const ScanContext = createContext<ScanContextValue | null>(null);

export function ScanProvider({ children }: PropsWithChildren) {
	const [status, setStatus] = useState<ScanStatus>({
		scheduled: EMPTY_PASS,
		manual: EMPTY_PASS,
	});
	const [pending, setPending] = useState(false);
	const [refused, setRefused] = useState("");
	const [now, setNow] = useState(Date.now() / 1000);
	const pollFast = pending || status.manual.queued;

	const refresh = useCallback(async function refresh() {
		try {
			setStatus(await getScan());
		} catch {
			// The active view reports connection failures; duplicating it in the sidebar adds nothing.
		}
	}, []);

	useEffect(() => {
		void refresh();
	}, [refresh]);

	useEffect(() => {
		const timer = window.setInterval(
			() => {
				if (!document.hidden) void refresh();
			},
			pollFast ? 1_000 : 10_000,
		);
		function visible() {
			if (!document.hidden) void refresh();
		}
		document.addEventListener("visibilitychange", visible);
		return () => {
			window.clearInterval(timer);
			document.removeEventListener("visibilitychange", visible);
		};
	}, [pollFast, refresh]);

	useEffect(() => {
		const timer = window.setInterval(() => setNow(Date.now() / 1000), 1_000);
		return () => window.clearInterval(timer);
	}, []);

	const start = useCallback(async function start(kind: "common" | "full", targets: string) {
		setPending(true);
		setRefused("");
		try {
			setStatus(await startScan(kind, targets));
			toast.success(`${kind === "full" ? "Full" : "Common-port"} scan queued`);
		} catch (caught) {
			const message = (caught as Error).message;
			setRefused(message);
			toast.error(`Could not start scan: ${message}`);
		} finally {
			setPending(false);
		}
	}, []);

	return <ScanContext.Provider value={{ status, pending, refused, now, start }}>{children}</ScanContext.Provider>;
}

export function useScan(): ScanContextValue {
	const context = useContext(ScanContext);
	if (!context) throw new Error("useScan must be used inside ScanProvider");
	return context;
}
