"use client";

import { useEffect, useRef, useState } from "react";

const DEFAULT_SIZE = 104;
const DEFAULT_STROKE = 8;

export function gradeColor(grade: string) {
  switch (grade) {
    case "A":
    case "B":
      return "var(--pass)";
    case "C":
    case "D":
      return "var(--warn)";
    default:
      return "var(--fail)";
  }
}

export function ScoreRing({
  score,
  grade,
  size = DEFAULT_SIZE,
  showLabel = true,
}: {
  score: number;
  grade: string;
  /** Defaults to the standard 104px report-page ring. Pass a smaller value
   * (e.g. for a compact theme-preview card) to render a scaled-down ring -
   * stroke width scales proportionally so it stays visually consistent. */
  size?: number;
  /** Hide the centered score/grade text - useful at small sizes where the
   * label text would no longer fit legibly. */
  showLabel?: boolean;
}) {
  const stroke = Math.max(3, Math.round((size / DEFAULT_SIZE) * DEFAULT_STROKE));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const [animatedScore, setAnimatedScore] = useState(0);
  const [dashOffset, setDashOffset] = useState(circumference);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    // Kick off on the next frame so the initial 0-state renders first,
    // letting the CSS transition on stroke-dashoffset actually animate.
    const id = requestAnimationFrame(() => {
      setDashOffset(circumference * (1 - Math.min(Math.max(score, 0), 100) / 100));
    });

    const start = performance.now();
    const duration = 900;
    function tick(now: number) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      // Round to 1 decimal (the same precision the backend stores), not to
      // a whole number - rounding to an integer here made the ring show
      // "76" for a 75.5 score while every other display on the page
      // (Recent Scans, Average Score, etc.) correctly showed "75.5".
      setAnimatedScore(Math.round(score * eased * 10) / 10);
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    }
    rafRef.current = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(id);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [score, size]);

  const color = gradeColor(grade);

  return (
    <div
      className="score-ring"
      style={{ width: size, height: size, "--ring-color": color } as React.CSSProperties}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--panel-border)"
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
          strokeDashoffset={dashOffset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(0.16, 1, 0.3, 1)" }}
        />
      </svg>
      {showLabel && (
        <div className="score-ring-label">
          <span className="num">{animatedScore}</span>
          <span className="grade" style={{ color }}>
            {grade}
          </span>
        </div>
      )}
    </div>
  );
}
