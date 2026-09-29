import type { PropsWithChildren } from "react";

export function EmptyState({ children }: PropsWithChildren) {
	return (
		<p className="empty" role="status">
			{children}
		</p>
	);
}
