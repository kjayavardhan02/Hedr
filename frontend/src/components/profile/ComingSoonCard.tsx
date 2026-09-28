export function ComingSoonCard({
  id,
  title,
  description,
}: {
  id: string;
  title: string;
  description: string;
}) {
  return (
    <div className="panel fade-in-up" id={id}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
        <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: 16 }}>{title}</h3>
        <span className="badge badge-INFO">Coming soon</span>
      </div>
      <p className="field-hint" style={{ margin: 0 }}>
        {description}
      </p>
    </div>
  );
}
