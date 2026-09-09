import { ConfidentialPanel } from "./confidential-panel";

export const metadata = {
  title: "Confidential scanning — RepoShield",
  description:
    "How RepoShield analyses a private repository inside a Chainlink CRE Trusted Execution Environment.",
};

export default function ConfidentialPage() {
  return (
    <div className="mx-auto max-w-4xl px-5 py-12">
      <ConfidentialPanel />
    </div>
  );
}
