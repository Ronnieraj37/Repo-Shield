import { gunzipSync } from "node:zlib";

/**
 * Minimal reader for the gzipped tarballs GitHub serves.
 *
 * This exists to collapse a scan from ~35 API requests to 3. Fetching files
 * one at a time is one request each, and GitHub's anonymous limit is 60 an
 * hour — so reading a thirty-file repository used up an hour's budget for
 * every visitor sharing the server's IP. The whole archive is one request.
 *
 * Node-only: `node:zlib` does not exist in the CRE WASM runtime, which is why
 * this lives outside `lib/analyzer` and outside `lib/github.ts`. The enclave
 * keeps fetching per-file — it runs one scan per invocation on the user's own
 * 5,000/hour budget, so the request count does not matter there.
 *
 * tar is a simple format: 512-byte header, then the file content padded up to
 * the next 512-byte boundary.
 */

const BLOCK = 512;

export interface TarEntry {
  path: string;
  content: Uint8Array;
}

export interface ExtractOptions {
  /** Skip any single file larger than this. */
  maxFileBytes?: number;
  /** Stop after this many files. */
  maxFiles?: number;
  /** Return false to skip a path without decoding it. */
  filter?: (path: string) => boolean;
}

export function extractTarGz(
  gzipped: Uint8Array,
  options: ExtractOptions = {},
): TarEntry[] {
  const maxFileBytes = options.maxFileBytes ?? 400_000;
  const maxFiles = options.maxFiles ?? 3000;

  const tar = new Uint8Array(gunzipSync(gzipped));
  const entries: TarEntry[] = [];

  let offset = 0;
  // Set by a preceding GNU long-name or pax header, consumed by the next entry.
  let pendingLongName: string | null = null;

  while (offset + BLOCK <= tar.length && entries.length < maxFiles) {
    const header = tar.subarray(offset, offset + BLOCK);

    // Two consecutive zero blocks mark the end of the archive.
    if (header.every((b) => b === 0)) break;

    const name = pendingLongName ?? readString(header, 0, 100);
    const size = readOctal(header, 124, 12);
    const typeFlag = String.fromCharCode(header[156] || 48);
    const prefix = readString(header, 345, 155);

    offset += BLOCK;
    const dataStart = offset;
    // Content is padded to a whole number of blocks.
    offset += Math.ceil(size / BLOCK) * BLOCK;

    if (typeFlag === "L") {
      // GNU long name: this entry's data *is* the next entry's path.
      pendingLongName = decodeText(tar.subarray(dataStart, dataStart + size)).replace(/\0+$/, "");
      continue;
    }
    if (typeFlag === "x" || typeFlag === "g") {
      // pax extended header: "<len> path=<value>\n" records.
      const record = decodeText(tar.subarray(dataStart, dataStart + size));
      const match = record.match(/\d+ path=(.+?)\n/);
      pendingLongName = match ? match[1] : null;
      continue;
    }

    pendingLongName = null;

    // "0" and NUL are regular files; everything else is a directory, link or
    // device node and has no contents worth reading.
    if (typeFlag !== "0" && typeFlag !== "\0") continue;

    const full = prefix ? `${prefix}/${name}` : name;
    // GitHub wraps everything in a `owner-repo-sha/` directory.
    const path = full.split("/").slice(1).join("/");
    if (!path) continue;
    if (size > maxFileBytes) continue;
    if (options.filter && !options.filter(path)) continue;

    entries.push({ path, content: tar.subarray(dataStart, dataStart + size) });
  }

  return entries;
}

function readString(block: Uint8Array, start: number, length: number): string {
  const raw = block.subarray(start, start + length);
  const end = raw.indexOf(0);
  return decodeText(end === -1 ? raw : raw.subarray(0, end));
}

function readOctal(block: Uint8Array, start: number, length: number): number {
  const text = readString(block, start, length).trim();
  if (!text) return 0;
  const value = parseInt(text, 8);
  return Number.isFinite(value) ? value : 0;
}

function decodeText(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
