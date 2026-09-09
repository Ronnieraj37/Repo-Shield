import type { ActionStep } from "@/lib/analyzer/types";
import { CopyButton } from "./copy-button";

/**
 * The part of the report a developer can act on.
 *
 * A severity badge tells someone they have a problem. This tells them what to
 * type. It sits above the findings list for exactly that reason.
 */
export function ActionPlan({ steps }: { steps: ActionStep[] }) {
  if (steps.length === 0) return null;

  return (
    <section className="panel p-5">
      <h2 className="text-sm font-semibold tracking-tight">What to do now</h2>
      <ol className="mt-4 space-y-4">
        {steps.map((step, index) => (
          <li key={step.title} className="flex gap-3">
            <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border border-[var(--color-border-strong)] font-mono text-[0.65rem] text-[var(--color-muted)]">
              {index + 1}
            </span>
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-medium">{step.title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-[var(--color-muted)]">
                {step.detail}
              </p>
              {step.command ? (
                <div className="mt-2 flex items-start gap-2">
                  <pre className="code-block flex-1">{step.command}</pre>
                  <CopyButton text={step.command} label="" className="!px-2.5 !py-2" />
                </div>
              ) : null}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
