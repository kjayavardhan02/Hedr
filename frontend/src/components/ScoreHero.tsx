import type { HeaderFinding } from "@/lib/types";
import { ScoreRing } from "./ScoreRing";

function takeaway(grade: string, failCount: number): string {
  if (grade === "A") return "Excellent — your header configuration meets the policy.";
  if (grade === "B") return "Good, with a little room to tighten things up.";
  if (grade === "C") return "Getting there — a few gaps are worth fixing.";
  if (failCount === 1) return "Close — just one check is holding the score back.";
  return "Needs attention — several checks failed against the policy.";
}

// Loose enough to accept both a live ScanResult and a saved ScanReport -
// this component only ever needs these fields from either shape.
interface ScoreHeroData {
  score: number;
  grade: string;
  policy_name: string;
  target: string | null;
  fetched_status_code: number | null;
  findings: HeaderFinding[];
}

// Colors the tinted variant the same way the comparison card is tinted.
function toneFor(grade: string): "up" | "warn" | "down" {
  if (grade === "A" || grade === "B") return "up";
  if (grade === "C" || grade === "D") return "warn";
  return "down";
}

export function ScoreHero({ result, tinted = false }: { result: ScoreHeroData; tinted?: boolean }) {
  const passCount = result.findings.filter((f) => f.status === "PASS").length;
  const failCount = result.findings.filter((f) => f.status === "FAIL").length;

  if (tinted) {
    return (
      <div className={`panel cmp-card cmp-card-${toneFor(result.grade)} fade-in-up`}>
        <div className="score-hero">
          <ScoreRing score={result.score} grade={result.grade} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 17, marginBottom: 4 }}>{result.policy_name}</div>
            <p style={{ margin: "0 0 6px", fontSize: 14 }}>{takeaway(result.grade, failCount)}</p>
            <div className="field-hint">
              {result.target ? (
                <>
                  Target: <span className="mono">{result.target}</span>
                  {result.fetched_status_code !== null && <> — HTTP {result.fetched_status_code}</>}
                </>
              ) : (
                "Parsed from pasted response"
              )}
            </div>
          </div>
        </div>
        <div className="cmp-tiles">
          <div className={`cmp-tile cmp-tile-good ${passCount === 0 ? "is-zero" : ""}`}>
            <span className="cmp-tile-value">{passCount}</span>
            <span className="cmp-tile-label">Passed</span>
          </div>
          <div className={`cmp-tile cmp-tile-bad ${failCount === 0 ? "is-zero" : ""}`}>
            <span className="cmp-tile-value">{failCount}</span>
            <span className="cmp-tile-label">Failed</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel fade-in-up">
      <div className="score-hero">
        <ScoreRing score={result.score} grade={result.grade} />
        <div>
          <div style={{ fontWeight: 700, fontSize: 17, marginBottom: 4 }}>
            {result.policy_name}
          </div>
          <p style={{ margin: "0 0 6px", fontSize: 14 }}>
            {takeaway(result.grade, failCount)}
          </p>
          <div className="field-hint">
            {result.target ? (
              <>
                Target: <span className="mono">{result.target}</span>
                {result.fetched_status_code !== null && (
                  <> — HTTP {result.fetched_status_code}</>
                )}
              </>
            ) : (
              "Parsed from pasted response"
            )}
          </div>
          <div style={{ marginTop: 8, fontSize: 13 }}>
            <span style={{ color: "var(--pass)" }}>{passCount} passed</span>
            {"  ·  "}
            <span style={{ color: "var(--fail)" }}>{failCount} failed</span>
          </div>
        </div>
      </div>
    </div>
  );
}
