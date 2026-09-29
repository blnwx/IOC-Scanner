import { Fragment, useRef } from "react";
import type { JarmRow } from "../types";
import { stamp } from "../utils";
import { InlineBlacklistForm } from "./InlineBlacklistForm";

interface JarmTableRowProps {
	row: JarmRow;
	banded: boolean;
	editing: boolean;
	onEdit: () => void;
	onClose: () => void;
	onSaved: () => void;
}

export function JarmTableRow({ row, banded, editing, onEdit, onClose, onSaved }: JarmTableRowProps) {
	const button = useRef<HTMLButtonElement>(null);
	function close() {
		onClose();
		queueMicrotask(() => button.current?.focus());
	}
	return (
		<Fragment>
			<tr className={banded ? "band" : undefined}>
				<td className="num">{row.hash}</td>
				<td className="num">{row.hosts.toLocaleString()}</td>
				<td className="num muted">{stamp(row.first_seen)}</td>
				<td className="num muted">{stamp(row.last_seen)}</td>
				<td className="act">
					<button
						ref={button}
						type="button"
						className={`ackbtn ${row.blacklisted ? "blacklisted-action" : "ack-action"}`}
						disabled={row.blacklisted || editing}
						aria-label={`${row.blacklisted ? "Blacklisted " : "Blacklist "}${row.hash}`}
						onClick={onEdit}
					>
						{row.blacklisted ? "BLACKLISTED" : "BLACKLIST"}
					</button>
				</td>
			</tr>
			{editing && (
				<tr className="detail">
					<td colSpan={5}>
						<InlineBlacklistForm
							row={row}
							onCancel={close}
							onSaved={() => {
								onClose();
								onSaved();
							}}
						/>
					</td>
				</tr>
			)}
		</Fragment>
	);
}
