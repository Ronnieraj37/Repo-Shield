import { Suspense } from "react";
import { ScanConsole } from "./scan-console";

export const metadata = { title: "Scan — RepoShield" };

export default function ScanPage() {
  return (
    <div className="mx-auto max-w-3xl px-5 py-12">
      <Suspense
        fallback={
          <div className="panel h-64 animate-pulse-dot" aria-label="Loading" />
        }
      >
        <ScanConsole />
      </Suspense>
    </div>
  );
}
