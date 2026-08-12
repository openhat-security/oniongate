import { invoke } from "@tauri-apps/api/core";
import { cn } from "@/lib/utils";

export function shortLocation(location: string) {
  if (!location) return "";
  const parts = location.replace(/\\/g, "/").split("/").filter(Boolean);
  if (parts.length <= 3) return location;
  return parts.slice(-3).join("/");
}

export function ProcessIdentity({
  name,
  pid,
  location,
  system,
  compact,
  onReveal,
}: {
  name: string;
  pid: number;
  location?: string;
  system?: boolean;
  compact?: boolean;
  onReveal?: (pid: number) => void;
}) {
  const loc = location?.trim() ?? "";
  const reveal = () => {
    if (onReveal) {
      onReveal(pid);
      return;
    }
    void invoke<string>("reveal_egress_path", { pid }).catch(() => {});
  };

  return (
    <div className={cn("min-w-0", compact ? "text-sm" : "")}>
      <div className="flex min-w-0 items-center gap-1.5">
        <span className="truncate font-semibold">{name}</span>
        {system ? (
          <span className="shrink-0 rounded-md bg-panel-2 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-muted">
            System
          </span>
        ) : null}
      </div>
      {loc ? (
        <button
          type="button"
          title={loc}
          onClick={reveal}
          className="mt-0.5 block max-w-full truncate text-left text-[11px] text-accent hover:underline"
        >
          {shortLocation(loc)}
        </button>
      ) : (
        <div className="mt-0.5 text-[11px] text-muted">pid {pid}</div>
      )}
    </div>
  );
}
