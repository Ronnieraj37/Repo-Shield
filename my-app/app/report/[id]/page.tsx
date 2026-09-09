import { ReportLoader } from "./report-loader";

export const metadata = { title: "Report — RepoShield" };

export default async function ReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <div className="mx-auto max-w-4xl px-5 py-10">
      <ReportLoader id={id} />
    </div>
  );
}
