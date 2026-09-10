"use client";

/**
 * Animated SVG workflow diagrams for the /demo deck.
 *
 * These carry the story the narrator won't read aloud: how a scan flows, what
 * the enclave keeps in vs. lets out, and how The Graph closes the loop. Motion
 * is CSS-only (flowing dashes, pulsing nodes) so nothing depends on a library.
 */

const C = {
  bg: "#0e1015",
  border: "#2c3242",
  text: "#e8eaf0",
  muted: "#9aa3b5",
  accent: "#4ade9b",
  danger: "#ff4d5e",
  purple: "#c4a3ff",
  amber: "#ffc53d",
};

function Node({
  x,
  y,
  w,
  h,
  label,
  sub,
  color = C.border,
  fill = C.bg,
  delay = 0,
}: {
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  sub?: string;
  color?: string;
  fill?: string;
  delay?: number;
}) {
  return (
    <g style={{ animation: `dg-pop 500ms ease-out ${delay}ms both` }}>
      <rect x={x} y={y} width={w} height={h} rx={10} fill={fill} stroke={color} strokeWidth={1.5} />
      <text
        x={x + w / 2}
        y={y + (sub ? h / 2 - 5 : h / 2 + 4)}
        textAnchor="middle"
        fill={C.text}
        fontSize={13}
        fontWeight={600}
        fontFamily="var(--font-sans)"
      >
        {label}
      </text>
      {sub ? (
        <text
          x={x + w / 2}
          y={y + h / 2 + 13}
          textAnchor="middle"
          fill={C.muted}
          fontSize={10}
          fontFamily="var(--font-mono)"
        >
          {sub}
        </text>
      ) : null}
    </g>
  );
}

function Flow({ d, color = C.accent, delay = 0 }: { d: string; color?: string; delay?: number }) {
  return (
    <path
      d={d}
      fill="none"
      stroke={color}
      strokeWidth={2}
      strokeDasharray="6 6"
      markerEnd="url(#dg-arrow)"
      style={{ animation: `dg-dash 700ms linear infinite, dg-fade 400ms ease ${delay}ms both` }}
    />
  );
}

function Defs() {
  return (
    <defs>
      <marker id="dg-arrow" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto">
        <path d="M0,0 L6,3 L0,6 Z" fill={C.muted} />
      </marker>
    </defs>
  );
}

const KEYFRAMES = `
@keyframes dg-dash { to { stroke-dashoffset: -24; } }
@keyframes dg-pop { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@keyframes dg-fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes dg-pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
`;

/* ─────────────────────────── Two-phase pipeline ─────────────────────────── */

export function PipelineDiagram() {
  return (
    <svg viewBox="0 0 900 260" className="w-full" role="img" aria-label="Two-phase scan pipeline">
      <style>{KEYFRAMES}</style>
      <Defs />
      <Node x={10} y={100} w={130} h={60} label="Paste a repo" sub="url · owner/repo" delay={0} />
      <Flow d="M145 130 L185 130" delay={100} />
      <Node x={190} y={100} w={140} h={60} label="Fetch archive" sub="1 request · 0 quota" color={C.accent} delay={150} />
      <Flow d="M335 130 L375 130" delay={250} />
      <Node x={380} y={100} w={150} h={60} label="Phase 1 · 38 rules" sub="static · offline" color={C.amber} delay={300} />

      {/* branch up to The Graph, down to Gemini */}
      <Flow d="M530 115 C 590 115, 590 55, 650 55" color={C.purple} delay={420} />
      <Node x={655} y={25} w={150} h={56} label="The Graph" sub="prior flags?" color={C.purple} delay={460} />
      <Flow d="M530 145 C 590 145, 590 200, 650 200" color={C.danger} delay={420} />
      <Node x={655} y={172} w={150} h={56} label="Phase 2 · Gemini" sub="reads flagged files" color={C.danger} delay={460} />

      {/* converge to verdict */}
      <Flow d="M805 53 C 850 60, 855 110, 835 122" color={C.purple} delay={560} />
      <Flow d="M805 200 C 850 190, 855 140, 835 138" color={C.danger} delay={560} />
      <g style={{ animation: "dg-pop 500ms ease-out 620ms both" }}>
        <rect x={835} y={100} width={55} height={60} rx={10} fill={C.bg} stroke={C.accent} strokeWidth={2} />
        <text x={862} y={126} textAnchor="middle" fill={C.accent} fontSize={20} fontWeight={700} fontFamily="var(--font-mono)">
          0
        </text>
        <text x={862} y={142} textAnchor="middle" fill={C.muted} fontSize={8} fontFamily="var(--font-mono)">
          –100
        </text>
      </g>
    </svg>
  );
}

/* ─────────────────────────── CRE enclave boundary ──────────────────────── */

export function EnclaveDiagram() {
  return (
    <svg viewBox="0 0 900 340" className="w-full" role="img" aria-label="Chainlink CRE enclave boundary">
      <style>{KEYFRAMES}</style>
      <Defs />

      {/* the enclave */}
      <g style={{ animation: "dg-pop 500ms ease-out 200ms both" }}>
        <rect x={260} y={20} width={380} height={300} rx={16} fill="rgba(74,222,155,0.05)" stroke={C.accent} strokeWidth={2} strokeDasharray="4 4" />
        <text x={450} y={46} textAnchor="middle" fill={C.accent} fontSize={12} fontWeight={600} fontFamily="var(--font-mono)" letterSpacing={1}>
          CHAINLINK CRE · AWS NITRO ENCLAVE
        </text>
        <Node x={330} y={130} w={240} h={70} label="analyzeRepo()" sub="the same engine as the app" color={C.accent} delay={500} />
        <text x={450} y={250} textAnchor="middle" fill={C.muted} fontSize={11} fontFamily="var(--font-sans)">
          sees the token, the source, every finding
        </text>
      </g>

      {/* goes in */}
      <g style={{ animation: "dg-pop 500ms ease-out 0ms both" }}>
        <text x={130} y={70} textAnchor="middle" fill={C.amber} fontSize={11} fontWeight={600} fontFamily="var(--font-mono)">
          VAULT DON
        </text>
        <text x={130} y={92} textAnchor="middle" fill={C.muted} fontSize={10} fontFamily="var(--font-mono)">GitHub token</text>
        <text x={130} y={108} textAnchor="middle" fill={C.muted} fontSize={10} fontFamily="var(--font-mono)">Gemini key</text>
        <text x={130} y={150} textAnchor="middle" fill={C.muted} fontSize={10} fontFamily="var(--font-mono)">private repo source</text>
      </g>
      <Flow d="M210 100 L258 120" delay={300} />
      <Flow d="M210 148 L258 150" delay={340} />

      {/* comes out */}
      <g style={{ animation: "dg-pop 500ms ease-out 700ms both" }}>
        <text x={770} y={140} textAnchor="middle" fill={C.accent} fontSize={11} fontWeight={600} fontFamily="var(--font-mono)">
          TO THE DON
        </text>
        <text x={770} y={162} textAnchor="middle" fill={C.text} fontSize={10} fontFamily="var(--font-mono)">threatScore</text>
        <text x={770} y={178} textAnchor="middle" fill={C.text} fontSize={10} fontFamily="var(--font-mono)">verdict · counts</text>
        <text x={770} y={200} textAnchor="middle" fill={C.muted} fontSize={9} fontFamily="var(--font-sans)">7 fields. nothing else.</text>
      </g>
      <Flow d="M642 165 L700 165" delay={760} />

      {/* the barrier note */}
      <g style={{ animation: "dg-pulse 2s ease-in-out infinite" }}>
        <text x={450} y={306} textAnchor="middle" fill={C.danger} fontSize={10} fontFamily="var(--font-mono)">
          findings quote source → they never leave
        </text>
      </g>
    </svg>
  );
}

/* ─────────────────────────── The Graph loop ────────────────────────────── */

export function GraphLoopDiagram() {
  return (
    <svg viewBox="0 0 900 300" className="w-full" role="img" aria-label="The Graph registry loop">
      <style>{KEYFRAMES}</style>
      <Defs />

      <Node x={20} y={120} w={150} h={60} label="Scan verdict" sub="danger · 100/100" color={C.danger} delay={0} />
      <Flow d="M175 150 L215 150" delay={100} />
      <Node x={220} y={120} w={160} h={60} label="ScanRegistry" sub="Sepolia · publish()" color={C.accent} delay={150} />
      <Flow d="M385 150 L425 150" delay={250} />
      <Node x={430} y={120} w={150} h={60} label="Subgraph" sub="indexes events" color={C.purple} delay={300} />
      <Flow d="M585 150 L625 150" delay={400} />
      <Node x={630} y={120} w={160} h={60} label="The Graph" sub="live query" color={C.purple} delay={450} />

      {/* loop back into the LLM */}
      <Flow d="M710 118 C 710 40, 300 40, 300 40" color={C.amber} delay={560} />
      <g style={{ animation: "dg-pop 500ms ease-out 600ms both" }}>
        <rect x={150} y={12} width={300} height={56} rx={10} fill={C.bg} stroke={C.amber} strokeWidth={1.5} />
        <text x={300} y={36} textAnchor="middle" fill={C.text} fontSize={13} fontWeight={600} fontFamily="var(--font-sans)">
          LLM reads it as a decision input
        </text>
        <text x={300} y={53} textAnchor="middle" fill={C.muted} fontSize={10} fontFamily="var(--font-mono)">
          &quot;has this repo — or its owner — been flagged?&quot;
        </text>
      </g>
      <Flow d="M300 68 C 300 90, 95 95, 95 118" color={C.amber} delay={640} />
      <g style={{ animation: "dg-pop 500ms ease-out 700ms both" }}>
        <rect x={20} y={120} width={150} height={60} rx={10} fill="none" stroke="none" />
      </g>

      <g style={{ animation: "dg-pulse 2s ease-in-out infinite" }}>
        <text x={450} y={250} textAnchor="middle" fill={C.amber} fontSize={11} fontFamily="var(--font-sans)">
          an owner with many flagged repos = a fake-recruitment operator
        </text>
        <text x={450} y={270} textAnchor="middle" fill={C.muted} fontSize={10} fontFamily="var(--font-sans)">
          invisible to any single-repo scan
        </text>
      </g>
    </svg>
  );
}
