import { recentDangerous, registryStats, graphConfigured } from "@/lib/graph";
import { RegistryView } from "./registry-view";

export const metadata = {
  title: "Community registry — RepoShield",
  description:
    "Repositories flagged by RepoShield, recorded onchain and indexed by The Graph.",
};

export const dynamic = "force-dynamic";

export default async function RegistryPage() {
  const available = graphConfigured();
  const [recent, stats] = available
    ? await Promise.all([recentDangerous(24), registryStats()])
    : [[], null];

  return (
    <div className="mx-auto max-w-4xl px-5 py-10">
      <RegistryView available={available} recent={recent} stats={stats} />
    </div>
  );
}
