export function CSPDirectives({ directives }: { directives: Record<string, string[]> }) {
  const entries = Object.entries(directives);

  if (entries.length === 0) {
    return <p className="field-hint">No directives to show.</p>;
  }

  return (
    <div className="csp-directives">
      {entries.map(([name, sources]) => (
        <div className="csp-directive-block" key={name}>
          <div className="csp-directive-name mono">{name}</div>
          {sources.length === 0 ? (
            <div className="csp-directive-source mono field-hint">
              (no sources — boolean directive)
            </div>
          ) : (
            sources.map((source, i) => (
              <div className="csp-directive-source mono" key={i}>
                - {source}
              </div>
            ))
          )}
        </div>
      ))}
    </div>
  );
}
