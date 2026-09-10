import { BigInt } from "@graphprotocol/graph-ts";
import { ScanPublished } from "../generated/ScanRegistry/ScanRegistry";
import { Repo, Publication, Registry } from "../generated/schema";

// Mirror the contract's Verdict enum onto readable strings.
const VERDICTS = ["Unknown", "Safe", "Caution", "Danger"];

function verdictName(v: i32): string {
  return v >= 0 && v < VERDICTS.length ? VERDICTS[v] : "Unknown";
}

export function handleScanPublished(event: ScanPublished): void {
  const repoId = event.params.repoId.toHexString();
  const verdict = verdictName(event.params.verdict);

  // Latest-per-repo, updated in place.
  let repo = Repo.load(repoId);
  const isNew = repo == null;
  if (repo == null) {
    repo = new Repo(repoId);
    repo.publishCount = 0;
  }
  repo.name = event.params.repo;
  repo.commit = event.params.commit;
  repo.threatScore = event.params.threatScore;
  repo.verdict = verdict;
  repo.reporter = event.params.reporter;
  repo.scannedAt = BigInt.fromI32(event.params.scannedAt.toI32());
  repo.publishCount = repo.publishCount + 1;
  repo.save();

  // Immutable feed entry.
  const pubId = event.transaction.hash.toHexString() + "-" + event.logIndex.toString();
  const pub = new Publication(pubId);
  pub.repo = repoId;
  pub.name = event.params.repo;
  pub.commit = event.params.commit;
  pub.threatScore = event.params.threatScore;
  pub.verdict = verdict;
  pub.reporter = event.params.reporter;
  pub.timestamp = event.block.timestamp;
  pub.txHash = event.transaction.hash;
  pub.save();

  // Global counters.
  let reg = Registry.load("global");
  if (reg == null) {
    reg = new Registry("global");
    reg.totalPublications = BigInt.zero();
    reg.dangerCount = BigInt.zero();
    reg.repoCount = BigInt.zero();
  }
  reg.totalPublications = reg.totalPublications.plus(BigInt.fromI32(1));
  if (verdict == "Danger") reg.dangerCount = reg.dangerCount.plus(BigInt.fromI32(1));
  if (isNew) reg.repoCount = reg.repoCount.plus(BigInt.fromI32(1));
  reg.save();
}
