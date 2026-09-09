"use client";

import { useEffect, useState } from "react";
import type { Verdict } from "@/lib/analyzer/types";
import { VERDICT_COLOR } from "./severity";

/**
 * The threat score, as a ring that fills on mount.
 *
 * The number is the headline of the whole report, so it animates from zero:
 * watching it climb to 87 lands differently than finding 87 already printed.
 */
export function ScoreRing({
  score,
  verdict,
  size = 168,
}: {
  score: number;
  verdict: Verdict;
  size?: number;
}) {
  const [displayed, setDisplayed] = useState(0);
  const color = VERDICT_COLOR[verdict];
  const stroke = 10;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;

  useEffect(() => {
    const duration = 900;
    const start = performance.now();
    let frame = 0;
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      // Ease-out cubic: fast at first, settles onto the final number.
      setDisplayed(Math.round(score * (1 - Math.pow(1 - t, 3))));
      if (t < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [score]);

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--color-border)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - (displayed / 100) * circumference}
          style={{ filter: `drop-shadow(0 0 8px color-mix(in srgb, ${color} 45%, transparent))` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-mono text-4xl font-semibold tabular-nums"
          style={{ color }}
        >
          {displayed}
        </span>
        <span className="mt-0.5 font-mono text-[0.65rem] uppercase tracking-[0.18em] text-[var(--color-faint)]">
          threat score
        </span>
      </div>
    </div>
  );
}
