import type { UseFormRegisterReturn } from "react-hook-form";

interface SettingProps {
	name: string;
	hint: string;
	registration: UseFormRegisterReturn;
	type?: string;
	rows?: number;
}

export function Setting({ name, hint, registration, type = "number", rows }: SettingProps) {
	const id = `set-${name === "refresh_seconds" ? "config" : "scan"}-${name}`;
	return (
		<div className="setting">
			<label className="name" htmlFor={id}>
				{name}
			</label>
			{rows ? <textarea id={id} rows={rows} {...registration} /> : <input id={id} type={type} min={type === "number" ? 1 : undefined} {...registration} />}
			<span className="hint">{hint}</span>
		</div>
	);
}
