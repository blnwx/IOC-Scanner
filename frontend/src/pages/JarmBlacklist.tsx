import { useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { changeBlacklist } from "../api";
import { EmptyState } from "../components/EmptyState";
import { Table } from "../components/Table";
import { useResource } from "../hooks/useResource";
import type { JarmBlacklistEntry } from "../types";
import { parseEntries } from "../utils";

export function JarmBlacklist() {
	const {
		data: rows,
		error,
		reload,
	} = useResource<JarmBlacklistEntry[]>("/api/jarm-blacklist", {
		poll: false,
		store: false,
	});
	const {
		register,
		handleSubmit,
		reset,
		formState: { isSubmitting },
	} = useForm<{ entries: string }>({ defaultValues: { entries: "" } });
	const [note, setNote] = useState<{ kind: string; text: string }>({
		kind: "",
		text: "",
	});
	const [removing, setRemoving] = useState("");
	const add = handleSubmit(async ({ entries: input }) => {
		let entries: JarmBlacklistEntry[];
		try {
			entries = parseEntries(input);
			if (!entries.length) throw new Error("Enter at least one Label,Hash item.");
		} catch (caught) {
			setNote({ kind: "bad", text: (caught as Error).message });
			return;
		}
		setNote({ kind: "", text: "Saving…" });
		try {
			await changeBlacklist("POST", entries);
			reset();
			setNote({ kind: "good", text: "Entries added." });
			toast.success(`${entries.length} ${entries.length === 1 ? "entry" : "entries"} added to the JARM blacklist`);
			reload();
		} catch (caught) {
			const message = (caught as Error).message;
			setNote({ kind: "bad", text: message });
			toast.error(`Could not update the JARM blacklist: ${message}`);
		}
	});

	async function remove(hash: string) {
		setRemoving(hash);
		setNote({ kind: "", text: "" });
		try {
			await changeBlacklist("DELETE", { hash });
			toast.success("Entry removed from the JARM blacklist");
			reload();
		} catch (caught) {
			const message = (caught as Error).message;
			setNote({ kind: "bad", text: message });
			toast.error(`Could not update the JARM blacklist: ${message}`);
		} finally {
			setRemoving("");
		}
	}

	if (!rows) return <EmptyState>{error || "Loading..."}</EmptyState>;
	return (
		<>
			<section id="form">
				<form className="form blacklist-form" onSubmit={(event) => void add(event)}>
					<div className="group">
						<h2>Add entries</h2>
						<div className="setting blacklist-input">
							<label className="name" htmlFor="jarm-blacklist-input">
								Entries
							</label>
							<textarea
								id="jarm-blacklist-input"
								rows={6}
								spellCheck={false}
								placeholder="CobaltStrike,27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
								disabled={isSubmitting}
								{...register("entries")}
							/>
							<span className="hint">One Label,Hash item per nonblank line; hashes are 62 hexadecimal characters.</span>
						</div>
					</div>
					<div className="actions">
						<button className="save" type="submit" disabled={isSubmitting}>
							Add to blacklist
						</button>
						<a className="save" href="/api/jarm-blacklist?format=csv" download="jarm-blacklist.csv">
							Export CSV
						</a>
						<span className={`note${note.kind ? ` ${note.kind}` : ""}`} role="status">
							{note.text}
						</span>
					</div>
					<p className="total">
						{rows.length.toLocaleString()} {rows.length === 1 ? "blacklisted fingerprint" : "blacklisted fingerprints"} · matches raise stored and future
						results to High
					</p>
				</form>
			</section>
			<Table headers={["Label", "JARM fingerprint", ""]}>
				{rows.map((row, index) => (
					<tr key={row.hash} className={index % 2 ? "band" : undefined}>
						<td className="ip blacklist-label">
							<span className="mark band-high" />
							{row.label}
						</td>
						<td className="num">{row.hash}</td>
						<td className="act">
							<button
								type="button"
								className="ackbtn reset-action"
								disabled={removing === row.hash}
								aria-label={`Remove ${row.label} from the JARM blacklist`}
								onClick={() => void remove(row.hash)}
							>
								REMOVE
							</button>
						</td>
					</tr>
				))}
			</Table>
			{!rows.length && <EmptyState>No fingerprints yet. Add a labeled JARM above to start matching.</EmptyState>}
		</>
	);
}
