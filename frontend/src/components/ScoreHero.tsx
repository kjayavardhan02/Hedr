import type { HeaderFinding, ScoreBreakdown } from "@/lib/types";
import { targetTypeLabel, type TargetType } from "@/lib/targetType";
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
  /** A raw-response scan's Target URL, when given - the address it's tagged
   * with for comparison purposes (never fetched). Null for a URL-mode scan,
   * whose `target` is already the fetched URL. */
  target_url?: string | null;
  fetched_status_code: number | null;
  findings: HeaderFinding[];
  /** Applicable/passed/failed/N/A counts; absent only on very old payloads. */
  breakdown?: ScoreBreakdown | null;
  target_type?: TargetType | null;
}

// Colors the tinted variant the same way the comparison card is tinted.
function toneFor(grade: string): "up" | "warn" | "down" {
  if (grade === "A" || grade === "B") return "up";
  if (grade === "C" || grade === "D") return "warn";
  return "down";
}

export function ScoreHero({ result, tinted = false }: { result: ScoreHeroData; tinted?: boolean }) {
  // Prefer the server's breakdown (it also counts the CSP check); fall back to
  // the header findings for payloads that predate it.
  const passCount = result.breakdown?.passed ?? result.findings.filter((f) => f.status === "PASS").length;
  const failCount = result.breakdown?.failed ?? result.findings.filter((f) => f.status === "FAIL").length;
  const naCount =
    result.breakdown?.not_applicable ?? result.findings.filter((f) => f.status === "NOT_APPLICABLE").length;
  const applicableCount = result.breakdown?.applicable ?? passCount + failCount;
  const targetTypeText = result.target_type ? targetTypeLabel(result.target_type) : null;

  if (tinted) {
    return (
      <div className={`panel cmp-card cmp-card-${toneFor(result.grade)} fade-in-up`}>
        <div className="score-hero">
          <ScoreRing score={result.score} grade={result.grade} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 17, marginBottom: 4, overflowWrap: "anywhere" }}>{result.policy_name}</div>
            <p style={{ margin: "0 0 6px", fontSize: 14 }}>{takeaway(result.grade, failCount)}</p>
            <div className="field-hint">
              {result.target ? (
                <>
                  Target: <span className="mono">{result.target}</span>
                  {result.target_url && <> · <span className="mono">{result.target_url}</span></>}
                  {result.fetched_status_code !== null && <> — HTTP {result.fetched_status_code}</>}
                </>
              ) : (
                "Parsed from pasted response"
              )}
            </div>
            {targetTypeText && (
              <div className="field-hint" style={{ marginTop: 2 }}>
                Target type: <strong>{targetTypeText}</strong>
              </div>
            )}
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
          {naCount > 0 && (
            <div className="cmp-tile is-zero">
              <span className="cmp-tile-value">{naCount}</span>
              <span className="cmp-tile-label">N/A</span>
            </div>
          )}
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
                {result.target_url && <> · <span className="mono">{result.target_url}</span></>}
                {result.fetched_status_code !== null && (
                  <> — HTTP {result.fetched_status_code}</>
                )}
              </>
            ) : (
              "Parsed from pasted response"
            )}
          </div>
          {targetTypeText && (
            <div className="field-hint" style={{ marginTop: 4 }}>
              Target type: <strong>{targetTypeText}</strong>
            </div>
          )}
          <div style={{ marginTop: 8, fontSize: 13 }}>
            <span style={{ color: "var(--pass)" }}>{passCount} passed</span>
            {"  ·  "}
            <span style={{ color: "var(--fail)" }}>{failCount} failed</span>
            {naCount > 0 && (
              <>
                {"  ·  "}
                <span style={{ color: "var(--text-dim)" }}>{naCount} N/A</span>
              </>
            )}
          </div>
          <div className="field-hint" style={{ marginTop: 4 }}>
            Score is based on {applicableCount} applicable check{applicableCount === 1 ? "" : "s"}
            {naCount > 0 ? `; ${naCount} not applicable ${naCount === 1 ? "is" : "are"} excluded` : ""}.
          </div>
        </div>
      </div>
    </div>
  );
}
