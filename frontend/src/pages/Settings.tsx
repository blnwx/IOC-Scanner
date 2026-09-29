import { EmptyState } from "../components/EmptyState";
import { SettingsForm } from "../components/SettingsForm";
import { useResource } from "../hooks/useResource";
import type { SettingsResponse } from "../types";

export function Settings() {
	const { data, error } = useResource<SettingsResponse>("/api/settings", {
		poll: false,
		store: false,
	});
	return data ? <SettingsForm data={data} /> : <EmptyState>{error || "Loading..."}</EmptyState>;
}
