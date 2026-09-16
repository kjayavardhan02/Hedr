import type { ScanResult } from "@/lib/types";
import { ScoreRing } from "./ScoreRing";

function takeaway(grade: string, failCount: number): string {
  if (grade === "A") return "Excellent — your header configuration meets the policy.";
  if (grade === "B") return "Good, with a little room to tighten things up.";
  if (grade === "C") return "Getting there — a few gaps are worth fixing.";
  if (failCount === 1) return "Close — just one check is holding the score back.";
  return "Needs attention — several checks failed against the policy.";
}

export function ScoreHero({ result }: { result: ScanResult }) {
  const passCount = result.findings.filter((f) => f.status === "PASS").length;
  const failCount = result.findings.filter((f) => f.status === "FAIL").length;

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
