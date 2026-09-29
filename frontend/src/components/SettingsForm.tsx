import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { saveSettings } from "../api";
import type { Config, SettingsResponse } from "../types";
import { items } from "../utils";
import { Setting } from "./Setting";

interface SettingsValues {
	refresh_seconds: string;
	targets_file: string;
	feed_only_targets_file: string;
	asn_refresh_minutes: string;
	scans_per_day: string;
	max_workers: string;
	dial_timeout_ms: string;
	tls_timeout_ms: string;
	jarm_timeout_ms: string;
	allow: string;
	deny: string;
	common_ports: string;
	domain_ignorelist: string;
}

function settingsValues(config: Config): SettingsValues {
	return {
		refresh_seconds: String(config.config.refresh_seconds),
		targets_file: config.scan.targets_file,
		feed_only_targets_file: config.scan.feed_only_targets_file,
		asn_refresh_minutes: String(config.scan.asn_refresh_minutes),
		scans_per_day: String(config.scan.scans_per_day),
		max_workers: String(config.scan.max_workers),
		dial_timeout_ms: String(config.scan.dial_timeout_ms),
		tls_timeout_ms: String(config.scan.tls_timeout_ms),
		jarm_timeout_ms: String(config.scan.jarm_timeout_ms),
		allow: config.scan.allow.join("\n"),
		deny: config.scan.deny.join("\n"),
		common_ports: config.scan.common_ports.join(" "),
		domain_ignorelist: config.feeds.domain_ignorelist.join("\n"),
	};
}

function number(value: string) {
	return value.trim() === "" ? 0 : Number(value);
}

export function SettingsForm({ data }: { data: SettingsResponse }) {
	const {
		register,
		handleSubmit,
		reset,
		formState: { isSubmitting },
	} = useForm<SettingsValues>({
		defaultValues: settingsValues(data.config),
	});
	const [loaded, setLoaded] = useState(data.config);
	const [note, setNote] = useState<{ kind: string; text: string }>({
		kind: "",
		text: "",
	});
	useEffect(() => {
		setLoaded(data.config);
		reset(settingsValues(data.config));
	}, [data.config, reset]);
	const submit = handleSubmit(async (values) => {
		const config: Config = {
			...loaded,
			config: {
				...loaded.config,
				refresh_seconds: number(values.refresh_seconds),
			},
			feeds: {
				...loaded.feeds,
				domain_ignorelist: items(values.domain_ignorelist),
			},
			scan: {
				...loaded.scan,
				targets_file: values.targets_file.trim(),
				feed_only_targets_file: values.feed_only_targets_file.trim(),
				asn_refresh_minutes: number(values.asn_refresh_minutes),
				scans_per_day: number(values.scans_per_day),
				max_workers: number(values.max_workers),
				dial_timeout_ms: number(values.dial_timeout_ms),
				tls_timeout_ms: number(values.tls_timeout_ms),
				jarm_timeout_ms: number(values.jarm_timeout_ms),
				allow: items(values.allow),
				deny: items(values.deny),
				common_ports: items(values.common_ports).map(Number),
			},
		};
		setNote({ kind: "", text: "Saving…" });
		try {
			const saved = await saveSettings(config);
			setLoaded(saved.config);
			reset(settingsValues(saved.config));
			setNote({ kind: "good", text: "Settings saved." });
			toast.success("Settings saved");
		} catch (caught) {
			const message = (caught as Error).message;
			setNote({ kind: "bad", text: message });
			toast.error(`Could not save settings: ${message}`);
		}
	});
	return (
		<section id="form">
			<form className="form" onSubmit={(event) => void submit(event)}>
				<div className="group">
					<h2>config</h2>
					<Setting name="refresh_seconds" hint="How often the config and targets files are re-read, in seconds." registration={register("refresh_seconds")} />
				</div>
				<div className="group">
					<h2>scan</h2>
					<Setting name="targets_file" type="text" hint="The JSON file the Targets page edits." registration={register("targets_file")} />
					<Setting
						name="feed_only_targets_file"
						type="text"
						hint="Optional JSON target file for direct feed matching only. A new file starts empty; leave blank to disable."
						registration={register("feed_only_targets_file")}
					/>
					<Setting
						name="asn_refresh_minutes"
						hint="How often ASN prefixes are refreshed from RIPEstat, in minutes (minimum 15)."
						registration={register("asn_refresh_minutes")}
					/>
					<Setting name="scans_per_day" hint="Sweeps per day, 1 to 24. The interval is 24h divided by this." registration={register("scans_per_day")} />
					<Setting
						name="max_workers"
						hint="Port dials in flight at once. More than the process has file descriptors for fails dials."
						registration={register("max_workers")}
					/>
					<Setting name="dial_timeout_ms" hint="How long to wait for a port to answer, in milliseconds." registration={register("dial_timeout_ms")} />
					<Setting
						name="tls_timeout_ms"
						hint="Budget for a TLS handshake, which only runs on a port that already answered."
						registration={register("tls_timeout_ms")}
					/>
					<Setting
						name="jarm_timeout_ms"
						hint="Budget for connecting and again reading within one JARM probe. A fingerprint is ten probes back to back."
						registration={register("jarm_timeout_ms")}
					/>
					<Setting
						name="allow"
						rows={4}
						hint="The guardrail: addresses, CIDRs, and ASNs (for example AS13335) the scanner may probe. A target outside every entry is never swept."
						registration={register("allow")}
					/>
					<Setting
						name="deny"
						rows={4}
						hint="Addresses, CIDRs, and ASNs (for example AS13335) carved out of the allowlist. One entry per line; may be empty."
						registration={register("deny")}
					/>
					<Setting
						name="common_ports"
						rows={3}
						hint="Tried first in a full scan, or alone with Scan common ports. Separate with spaces."
						registration={register("common_ports")}
					/>
				</div>
				<div className="group">
					<h2>feeds</h2>
					<Setting
						name="domain_ignorelist"
						rows={4}
						hint="Feed indicators under these domains are removed. Enter one registrable or pseudo-domain per line; may be empty."
						registration={register("domain_ignorelist")}
					/>
					<div className="setting">
						<span className="name">threatfox_auth_key</span>
						<span className="fixed">{data.threatfox_auth_key_set ? "set" : "not set"}</span>
						<span className="hint">Edit config.toml to change it. This page has no authentication, so it never handles the key.</span>
					</div>
				</div>
				<div className="actions">
					<button className="save" type="submit" disabled={isSubmitting}>
						Save settings
					</button>
					<span className={`note${note.kind ? ` ${note.kind}` : ""}`}>{note.text}</span>
				</div>
			</form>
		</section>
	);
}
