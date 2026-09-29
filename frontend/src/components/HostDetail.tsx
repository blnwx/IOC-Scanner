import { Fragment } from "react";
import { virusTotalAddress, virusTotalDomain } from "../host-utils";
import type { Host } from "../types";
import { day, groups, stamp } from "../utils";
import { DetailEntry } from "./DetailEntry";
import { SignalReason } from "./SignalReason";

export function HostDetail({ host, feedOnly = false }: { host: Host; feedOnly?: boolean }) {
	const hostOnly = host.signals.filter(
		(signal) =>
			!host.ports.some(
				(port) => port.fingerprint && (port.signals || []).some((portSignal) => portSignal.source === signal.source && portSignal.value === signal.value),
			),
	);
	const certificates = [...host.ports.filter((port) => port.fingerprint)].sort((left, right) => Number(Boolean(right.band)) - Number(Boolean(left.band)));
	const bare = host.ports.filter((port) => !port.fingerprint);
	return (
		<>
			<p className="hostlookup">
				<a className="lookup" href={virusTotalAddress(host.ip)} target="_blank" rel="noopener noreferrer">
					Look up {host.ip} on VirusTotal
				</a>
			</p>
			{!feedOnly && !host.ports.length && <p className="muted">No open ports recorded.</p>}
			{host.port_count > host.ports.length && (
				<p className="muted">
					Answers on {host.port_count.toLocaleString()} ports. Showing the first {host.ports.length} — a host responding on nearly everything is not a real
					surface.
				</p>
			)}
			{hostOnly.length > 0 && (
				<div className="record">
					<h3>Feed hits on {host.ip}</h3>
					{hostOnly.map((signal) => (
						<SignalReason
							key={`${signal.source}-${signal.value}-${signal.tag}-${signal.first_seen || ""}`}
							signal={signal}
							ip={host.ip}
							showValue
							trailing={host.ports.some((port) => signal.value === `${host.ip}:${port.port}`) ? "  — seen open" : ""}
						/>
					))}
				</div>
			)}
			{certificates.map((port) => {
				const subjectLookup = virusTotalDomain(port.subject);
				return (
					<div className="record" key={port.port}>
						<h3>
							{host.ip}:{port.port}
							{port.band && (
								<>
									{" "}
									<span className={`band-${port.band}`}>flagged</span>
								</>
							)}
						</h3>
						<dl>
							<DetailEntry
								label="Subject"
								value={
									subjectLookup ? (
										<>
											{port.subject}{" "}
											<a className="lookup" href={subjectLookup} target="_blank" rel="noopener noreferrer" aria-label={`Look up ${port.subject} on VirusTotal`}>
												VirusTotal
											</a>
										</>
									) : (
										port.subject
									)
								}
							/>
							<DetailEntry label="Issuer" value={port.issuer} />
							<DetailEntry label="SANs" value={port.dns_names} />
							<DetailEntry label="Valid" value={`${day(port.not_before)} → ${day(port.not_after)}${port.self_signed ? "  (self-signed)" : ""}`} />
							<DetailEntry label="Signature" value={port.signature_algorithm} />
							<DetailEntry label="Serial" value={port.serial_number} />
							<DetailEntry label="SHA-1" value={groups(port.fingerprint)} />
							<DetailEntry label="JARM" value={port.jarm} />
							<DetailEntry label="Scanned (UTC)" value={stamp(port.scanned_at)} />
							<dt>Reasons</dt>
							{port.signals?.length ? (
								<dd>
									{port.signals.map((signal) => (
										<SignalReason key={`${signal.source}-${signal.value}-${signal.tag}`} signal={signal} ip={host.ip} />
									))}
								</dd>
							) : port.band ? (
								<dd>A feed names this address and port. Listed below.</dd>
							) : (
								<dd className="muted">Certificate passed every check.</dd>
							)}
						</dl>
					</div>
				);
			})}
			{bare.length > 0 && (
				<div className="record">
					<h3>Open, no TLS handshake</h3>
					<div className="portlist">
						{bare.map((port, index) => (
							<Fragment key={port.port}>
								{index > 0 && " "}
								<span className={port.band ? `port-flag ${port.band}` : "port-clean"}>
									{port.port}
									{port.jarm ? ` jarm=${port.jarm}` : ""}
								</span>
							</Fragment>
						))}
					</div>
					<p className="muted">Nothing answered a TLS handshake here, so there is no certificate to check.</p>
				</div>
			)}
		</>
	);
}
