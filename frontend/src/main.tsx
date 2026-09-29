import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App";
import { ScanProvider } from "./context/ScanContext";
import "sonner/dist/styles.css";
import "./app.css";
import "./table.css";
import "./forms.css";
import "./analytics.css";

const root = document.getElementById("root");
if (!root) throw new Error("dashboard root is missing");

createRoot(root).render(
	<StrictMode>
		<BrowserRouter>
			<ScanProvider>
				<App />
			</ScanProvider>
		</BrowserRouter>
	</StrictMode>,
);
