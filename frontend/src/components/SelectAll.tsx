import { useEffect, useRef } from "react";
import { Tooltip } from "./Tooltip";

interface SelectAllProps {
	checked: boolean;
	indeterminate: boolean;
	disabled: boolean;
	tooltip: string;
	onChange: (checked: boolean) => void;
}

export function SelectAll({ checked, indeterminate, disabled, tooltip, onChange }: SelectAllProps) {
	const ref = useRef<HTMLInputElement>(null);
	useEffect(() => {
		if (ref.current) ref.current.indeterminate = indeterminate;
	}, [indeterminate]);
	return (
		<Tooltip content={tooltip}>
			<input
				ref={ref}
				type="checkbox"
				aria-label="Select all compatible rows"
				checked={checked}
				disabled={disabled}
				onChange={(event) => onChange(event.target.checked)}
			/>
		</Tooltip>
	);
}
