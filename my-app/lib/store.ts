"use client";

import { useSyncExternalStore } from "react";
import type { ThreatReport } from "./analyzer/types";

/**
 * Scan history, in the developer's own browser.
 *
 * Reports about someone's private repository do not belong on our server, so
 * they are never sent there. `localStorage` is the whole persistence layer:
 * it survives reloads, it is per-device by design, and there is no copy of it
 * anywhere else. Clearing site data is a complete and irreversible delete.
 *
 * Exposed as an external store rather than read inside an effect, so React can
 * subscribe to it directly. That also means a scan run in one tab shows up in
 * the history list of another one, for free.
 */

const KEY = "reposhield.reports.v1";
const MAX_REPORTS = 30;

export interface StoredReport {
  report: ThreatReport;
  savedAt: string;
}

const EMPTY: StoredReport[] = [];

/**
 * `useSyncExternalStore` compares snapshots by identity and will loop forever
 * if `getSnapshot` parses fresh JSON on every call. So the parsed value is
 * cached and only rebuilt when the raw string actually changes.
 */
let cachedRaw: string | null = null;
let cachedValue: StoredReport[] = EMPTY;

const listeners = new Set<() => void>();

function readRaw(): string | null {
  try {
    return window.localStorage.getItem(KEY);
  } catch {
    // Private windows and blocked site data both land here. An empty history
    // is a correct render, so this must never throw into the UI.
    return null;
  }
}

function getSnapshot(): StoredReport[] {
  const raw = readRaw();
  if (raw === cachedRaw) return cachedValue;
  cachedRaw = raw;
  if (!raw) {
    cachedValue = EMPTY;
    return cachedValue;
  }
  try {
    const parsed = JSON.parse(raw) as StoredReport[];
    cachedValue = Array.isArray(parsed) ? parsed : EMPTY;
  } catch {
    cachedValue = EMPTY;
  }
  return cachedValue;
}

/** There is no history on the server; the client fills it in on hydration. */
function getServerSnapshot(): StoredReport[] {
  return EMPTY;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // `storage` fires for changes made in *other* tabs; same-tab writes notify
  // through `emit()` below.
  window.addEventListener("storage", emit);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) window.removeEventListener("storage", emit);
  };
}

function emit(): void {
  for (const listener of listeners) listener();
}

function write(reports: StoredReport[]): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(reports.slice(0, MAX_REPORTS)));
  } catch {
    // Quota exceeded or storage blocked. The scan still succeeded and is on
    // screen; losing the history entry is not worth an error dialog.
  }
  emit();
}

export function saveReport(report: ThreatReport): void {
  const existing = getSnapshot().filter((r) => r.report.id !== report.id);
  write([{ report, savedAt: new Date().toISOString() }, ...existing]);
}

export function deleteReport(id: string): void {
  write(getSnapshot().filter((r) => r.report.id !== id));
}

export function clearReports(): void {
  try {
    window.localStorage.removeItem(KEY);
  } catch {
    // Nothing to do; the next snapshot reads empty either way.
  }
  emit();
}

/** All stored reports, newest first. */
export function useReports(): StoredReport[] {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

/**
 * One report, or `null` if this device has never scanned it.
 *
 * `undefined` during the server render and first paint, so the caller can show
 * a skeleton instead of flashing "not found" before hydration.
 */
export function useReport(id: string): ThreatReport | null | undefined {
  const hydrated = useSyncExternalStore(
    subscribe,
    () => true,
    () => false,
  );
  const reports = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  if (!hydrated) return undefined;
  return reports.find((r) => r.report.id === id)?.report ?? null;
}
