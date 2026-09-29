import { lazy } from "react";
import { Navigate, Route, Routes } from "react-router";
import { Toaster } from "sonner";
import { DashboardLayout } from "./components/DashboardLayout";
import { Hosts } from "./pages/Hosts";
import { Jarm } from "./pages/Jarm";
import { Logs } from "./pages/Logs";

const Domains = lazy(() => import("./pages/Domains").then((module) => ({ default: module.Domains })));
const Analytics = lazy(() => import("./pages/Analytics").then((module) => ({ default: module.Analytics })));
const JarmBlacklist = lazy(() =>
	import("./pages/JarmBlacklist").then((module) => ({
		default: module.JarmBlacklist,
	})),
);
const Settings = lazy(() => import("./pages/Settings").then((module) => ({ default: module.Settings })));
const Targets = lazy(() => import("./pages/Targets").then((module) => ({ default: module.Targets })));

export default function App() {
	return (
		<>
			<Routes>
				<Route path="/" element={<Navigate to="/hosts" replace />} />
				<Route element={<DashboardLayout />}>
					<Route path="hosts" element={<Hosts />} />
					<Route path="hosts/feed-only" element={<Hosts feedOnly />} />
					<Route path="domains" element={<Domains />} />
					<Route path="analytics" element={<Analytics />} />
					<Route path="jarm" element={<Jarm />} />
					<Route path="jarm-blacklist" element={<JarmBlacklist />} />
					<Route path="log" element={<Logs />} />
					<Route path="settings" element={<Settings />} />
					<Route path="targets" element={<Targets />} />
				</Route>
				<Route path="*" element={<Navigate to="/hosts" replace />} />
			</Routes>
			<Toaster position="top-right" richColors closeButton duration={4000} />
		</>
	);
}
