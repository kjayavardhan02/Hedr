"use client";

import { useEffect, useRef, useState } from "react";

const SIZE = 104;
const STROKE = 8;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function gradeColor(grade: string) {
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

export function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const [dashOffset, setDashOffset] = useState(CIRCUMFERENCE);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    // Kick off on the next frame so the initial 0-state renders first,
    // letting the CSS transition on stroke-dashoffset actually animate.
    const id = requestAnimationFrame(() => {
      setDashOffset(CIRCUMFERENCE * (1 - Math.min(Math.max(score, 0), 100) / 100));
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
  }, [score]);

  const color = gradeColor(grade);

  return (
    <div
      className="score-ring"
      style={{ width: SIZE, height: SIZE, "--ring-color": color } as React.CSSProperties}
    >
      <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`}>
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke="var(--panel-border)"
          strokeWidth={STROKE}
        />
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={dashOffset}
          transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}
          style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(0.16, 1, 0.3, 1)" }}
        />
      </svg>
      <div className="score-ring-label">
        <span className="num">{animatedScore}</span>
        <span className="grade" style={{ color }}>
          {grade}
        </span>
      </div>
    </div>
  );
}
