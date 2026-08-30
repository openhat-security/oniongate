import type { ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { cn } from "@/lib/utils";

export type ProjectLinkId = "docs" | "github" | "license";

/** Opens an allowlisted docs, GitHub, or license page. The UI never sends a URL. */
export function ProjectLink({
  link,
  children,
  className,
}: {
  link: ProjectLinkId;
  children: ReactNode;
  className?: string;
}) {
  return (
    <button
      type="button"
      className={cn(
        "bg-transparent p-0 text-left underline-offset-2 transition-colors hover:underline",
        className,
      )}
      onClick={() => {
        void invoke("open_project_link", { link });
      }}
    >
      {children}
    </button>
  );
}
