import { type FormEvent, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { changeBlacklist } from "../api";
import type { JarmRow } from "../types";

interface InlineBlacklistFormProps {
	row: JarmRow;
	onCancel: () => void;
	onSaved: () => void;
}

export function InlineBlacklistForm({ row, onCancel, onSaved }: InlineBlacklistFormProps) {
	const input = useRef<HTMLInputElement>(null);
	const [label, setLabel] = useState("");
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState("");
	useEffect(() => input.current?.focus(), []);

	async function submit(event: FormEvent) {
		event.preventDefault();
		const trimmed = label.trim();
		if (!trimmed) {
			setError("Enter a label.");
			queueMicrotask(() => input.current?.focus());
			return;
		}
		setError("");
		setIsSubmitting(true);
		try {
			await changeBlacklist("POST", [{ label: trimmed, hash: row.hash }]);
			toast.success("Entry added to the JARM blacklist");
			onSaved();
		} catch (caught) {
			const message = (caught as Error).message;
			setError(message);
			toast.error(`Could not update the JARM blacklist: ${message}`);
			queueMicrotask(() => input.current?.focus());
		} finally {
			setIsSubmitting(false);
		}
	}

	return (
		<form className="addbar" onSubmit={(event) => void submit(event)}>
			<input
				placeholder="Label"
				autoComplete="off"
				aria-label={`Label for ${row.hash}`}
				disabled={isSubmitting}
				ref={input}
				value={label}
				onChange={(event) => setLabel(event.target.value)}
			/>
			<button type="submit" disabled={isSubmitting}>
				Add to blacklist
			</button>
			<button type="button" disabled={isSubmitting} onClick={onCancel}>
				Cancel
			</button>
			<span className={`note${error ? " bad" : ""}`} role="status">
				{isSubmitting ? "Saving…" : error}
			</span>
		</form>
	);
}
