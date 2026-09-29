import { Fragment, useEffect, useState } from "react";
import { useFieldArray, useForm, useWatch } from "react-hook-form";
import { toast } from "sonner";
import { saveTargets } from "../api";
import type { TargetRow, TargetsResponse } from "../types";
import { items, parseTarget } from "../utils";
import { EmptyState } from "./EmptyState";
import { Table } from "./Table";

interface TargetValues {
	targets: TargetRow[];
	next: string;
}

export function TargetEditor({ data, feedOnly = false, onSaved }: { data: TargetsResponse; feedOnly?: boolean; onSaved?: () => void }) {
	// Both lists are edited on the same page, so element ids carry which editor they belong to.
	const scope = feedOnly ? "feed-only" : "active";
	const {
		control,
		register,
		getValues,
		setValue,
		handleSubmit,
		reset,
		formState: { isSubmitting },
	} = useForm<TargetValues>({
		defaultValues: { targets: data.targets, next: "" },
	});
	const { fields, append, remove } = useFieldArray({
		control,
		name: "targets",
	});
	const targets = useWatch({ control, name: "targets" }) || [];
	const [scannable, setScannable] = useState(data.scannable);
	const [dirty, setDirty] = useState(false);
	const [expanded, setExpanded] = useState<Set<string>>(new Set());
	const [note, setNote] = useState<{ kind: string; text: string }>({
		kind: "",
		text: "",
	});
	useEffect(() => {
		reset({ targets: data.targets, next: "" });
		setScannable(data.scannable);
		setDirty(false);
		setExpanded(new Set());
	}, [data, reset]);

	// Accepts several targets at once: whitespace- or comma-separated.
	function add() {
		const input = getValues("next");
		const parts = items(input);
		if (!parts.length) return;
		const seen = new Set(targets.map((row) => row.value));
		const bad: string[] = [];
		const added: TargetRow[] = [];
		for (const part of parts) {
			const entry = parseTarget(part);
			if (!entry || seen.has(entry.value)) {
				bad.push(part);
				continue;
			}
			seen.add(entry.value);
			added.push(entry);
		}
		if (added.length) {
			append(added);
			setDirty(true);
			setValue("next", "");
		}
		setNote(bad.length ? { kind: "bad", text: `Skipped (invalid or already listed): ${bad.join(", ")}` } : { kind: "", text: "" });
		queueMicrotask(() => document.getElementById(`add-target-${scope}`)?.focus());
	}

	const submit = handleSubmit(async (values) => {
		setNote({ kind: "", text: "Saving…" });
		try {
			const saved = await saveTargets(
				values.targets.map((row) => row.value),
				feedOnly,
			);
			reset({ targets: saved.targets, next: "" });
			setScannable(saved.scannable);
			setDirty(false);
			setExpanded(new Set());
			setNote({
				kind: "good",
				text: feedOnly ? "Feed-only targets saved." : "Targets saved. The next sweep uses them.",
			});
			toast.success("Targets saved");
			// The other editor's statuses are read against this list, so its rows are now stale.
			onSaved?.();
		} catch (caught) {
			const message = (caught as Error).message;
			setNote({ kind: "bad", text: message });
			toast.error(`Could not save targets: ${message}`);
		}
	});
	const count = `${targets.length.toLocaleString()} ${targets.length === 1 ? "target" : "targets"}`;
	return (
		<form className="target-editor" onSubmit={(event) => void submit(event)}>
			<section id={`form-${scope}`}>
				<div className="addbar">
					<input
						id={`add-target-${scope}`}
						placeholder="192.0.2.0/24, 198.51.100.7, AS13335"
						aria-label="Addresses, CIDRs, or ASNs to add, separated by spaces or commas"
						autoComplete="off"
						disabled={isSubmitting}
						{...register("next")}
						onKeyDown={(event) => {
							if (event.key === "Enter") {
								event.preventDefault();
								add();
							}
						}}
					/>
					<button type="button" disabled={isSubmitting} onClick={add}>
						Add targets
					</button>
				</div>
				<div className="actions">
					<button className="save" type="submit" disabled={isSubmitting}>
						Save targets
					</button>
					<span className={`note${note.kind ? ` ${note.kind}` : ""}`}>{note.text}</span>
					<span className="muted">Written to {data.targets_file}</span>
				</div>
				<p className="total">
					{dirty
						? `${count} · unsaved changes, save to see what is in scope`
						: `${count} · ${scannable.toLocaleString()} ${scannable === 1 ? "address" : "addresses"} in scope`}
				</p>
			</section>
			<Table headers={["Target", "Addresses", "Status", ""]} actionClass="">
				{fields.map((row, index) => {
					const isASN = /^AS\d+$/.test(row.value);
					const open = expanded.has(row.id);
					const childIDs = row.expansion.map((_, child) => `target-prefix-${scope}-${row.id}-${child}`);
					return (
						<Fragment key={row.id}>
							<tr className={index % 2 ? "band" : undefined}>
								<td className="ip">
									{isASN && (
										<button
											type="button"
											className="target-toggle"
											disabled={!row.expansion.length}
											aria-expanded={open}
											aria-controls={childIDs.join(" ") || undefined}
											aria-label={`${open ? "Collapse" : "Expand"} ${row.value} prefixes`}
											onClick={() =>
												setExpanded((current) => {
													const next = new Set(current);
													if (open) next.delete(row.id);
													else next.add(row.id);
													return next;
												})
											}
										>
											{open ? "▾" : "▸"}
										</button>
									)}
									{row.value}
								</td>
								<td className="num muted">
									{row.status === "unresolved" ? "—" : row.addresses.toLocaleString()}
									{row.expansion.length > 1 && ` · ${row.expansion.length.toLocaleString()} prefixes`}
								</td>
								<td className={`t-${row.status.replace(/ /g, "-")}`}>
									<span className="mark" />
									{row.status === "covered" && row.covered_by ? `covered by ${row.covered_by}` : row.status}
								</td>
								<td className="num t-remove">
									<button
										type="button"
										className="ackbtn reset-action"
										disabled={isSubmitting}
										aria-label={`Remove ${row.value}`}
										onClick={() => {
											remove(index);
											setDirty(true);
											setNote({ kind: "", text: "" });
										}}
									>
										REMOVE
									</button>
								</td>
							</tr>
							{open &&
								row.expansion.map((prefix, child) => (
									<tr id={childIDs[child]} key={prefix.value} className={`target-prefix${index % 2 ? " band" : ""}`}>
										<td className="ip">{prefix.value}</td>
										<td className="num muted">{prefix.addresses.toLocaleString()}</td>
										<td className={`t-${prefix.status.replace(/ /g, "-")}`}>
											<span className="mark" />
											{prefix.status}
										</td>
										<td />
									</tr>
								))}
						</Fragment>
					);
				})}
			</Table>
			{!fields.length && <EmptyState>{feedOnly ? "No feed-only targets." : "No targets. The scanner has nothing to sweep until one is added."}</EmptyState>}
		</form>
	);
}
