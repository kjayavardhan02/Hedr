import type { CSSProperties, ReactNode } from "react";

export function ComingSoonCard({
  id,
  title,
  description,
  icon,
  style,
}: {
  id: string;
  title: string;
  description: string;
  icon: ReactNode;
  style?: CSSProperties;
}) {
  return (
    <div className="panel fade-in-up" id={id} style={style}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
        <h3 className="section-title" style={{ margin: 0 }}>
          <span className="section-icon">{icon}</span>
          {title}
        </h3>
        <span className="badge badge-INFO">Coming soon</span>
      </div>
      <p className="field-hint" style={{ margin: "8px 0 0" }}>
        {description}
      </p>
    </div>
  );
}
