"use client";

import Link from "next/link";
import { ReportView } from "@/components/report-view";
import { useReport } from "@/lib/store";

/**
 * Reports live in the browser, so this reads them there.
 *
 * The consequence is that a report URL is not shareable, which is the correct
 * trade: a scan of someone's private repository should not be fetchable by
 * anyone who guesses an id. Sharing happens through the explicit Markdown and
 * JSON exports on the report itself.
 */
export function ReportLoader({ id }: { id: string }) {
  const report = useReport(id);

  if (report === undefined) {
    return <div className="panel h-72 animate-pulse-dot" aria-label="Loading report" />;
  }

  if (report === null) {
    return (
      <div className="panel p-8 text-center">
        <h1 className="text-lg font-medium">This report is not on this device</h1>
        <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-[var(--color-muted)]">
          Reports are stored in your browser and never uploaded, so they do not
          follow you between devices or survive clearing site data. Run the scan
          again to regenerate it.
        </p>
        <Link href="/scan" className="btn btn-primary mt-5">
          Scan a repository
        </Link>
      </div>
    );
  }

  return <ReportView report={report} />;
}
