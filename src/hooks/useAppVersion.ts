import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";

/** Bundled application version from Tauri (the downloaded build). */
export function useAppVersion(): string | null {
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    void getVersion()
      .then(setVersion)
      .catch(() => setVersion(null));
  }, []);
  return version;
}
