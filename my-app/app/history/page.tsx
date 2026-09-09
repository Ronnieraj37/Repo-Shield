import { HistoryList } from "./history-list";

export const metadata = { title: "History — RepoShield" };

export default function HistoryPage() {
  return (
    <div className="mx-auto max-w-4xl px-5 py-10">
      <HistoryList />
    </div>
  );
}
