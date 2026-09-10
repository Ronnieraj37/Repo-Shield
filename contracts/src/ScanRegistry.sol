// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ScanRegistry
/// @notice A public, append-only registry of RepoShield scan verdicts.
///
/// RepoShield analyses an unfamiliar GitHub repository and decides whether it
/// is safe to run. This contract lets those verdicts live somewhere public and
/// permanent: once a repo is flagged, the next candidate who is sent the same
/// repository can find that out before running anything — even from a
/// different machine, a different tool, or after the original scanner is gone.
///
/// The verdicts are indexed by a subgraph on The Graph, which is what the
/// RepoShield app queries to show "has anyone flagged this commit?" and to list
/// recently flagged repositories.
///
/// There is no access control by design. This is a public bulletin board on a
/// testnet; anyone may publish, and every entry records who reported it.
contract ScanRegistry {
    enum Verdict {
        Unknown, // 0 — never used; guards against an unset value
        Safe, // 1
        Caution, // 2
        Danger // 3
    }

    struct Scan {
        bytes32 commit; // the commit SHA that was analysed (first 32 bytes)
        uint16 threatScore; // 0–100
        Verdict verdict;
        uint40 scannedAt; // block timestamp of the most recent publish
        address reporter; // who published this verdict
        uint32 count; // how many times this repo has been published
    }

    /// @notice Latest verdict per repository, keyed by keccak256("owner/repo").
    mapping(bytes32 => Scan) public latest;

    /// @notice Total number of publish() calls, across all repositories.
    uint256 public totalPublications;

    event ScanPublished(
        bytes32 indexed repoId,
        string repo,
        bytes32 commit,
        uint16 threatScore,
        Verdict verdict,
        address indexed reporter,
        uint40 scannedAt
    );

    error InvalidVerdict();
    error ScoreTooHigh();

    /// @notice Publish a scan verdict for `repo` at `commit`.
    /// @param repo Full name, e.g. "owner/name". Emitted so indexers need no
    ///             off-chain lookup to recover it from the hashed id.
    /// @param commit The analysed commit SHA (its first 32 bytes).
    /// @param threatScore 0–100.
    /// @param verdict Safe, Caution, or Danger.
    function publish(string calldata repo, bytes32 commit, uint16 threatScore, Verdict verdict) external {
        if (verdict == Verdict.Unknown) revert InvalidVerdict();
        if (threatScore > 100) revert ScoreTooHigh();

        bytes32 repoId = keccak256(bytes(repo));
        Scan storage prev = latest[repoId];

        latest[repoId] = Scan({
            commit: commit,
            threatScore: threatScore,
            verdict: verdict,
            scannedAt: uint40(block.timestamp),
            reporter: msg.sender,
            count: prev.count + 1
        });
        unchecked {
            totalPublications++;
        }

        emit ScanPublished(repoId, repo, commit, threatScore, verdict, msg.sender, uint40(block.timestamp));
    }

    /// @notice Convenience read: the current verdict for a repository name.
    function verdictOf(string calldata repo) external view returns (Scan memory) {
        return latest[keccak256(bytes(repo))];
    }
}
