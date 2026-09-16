export function Skeleton({ height = 16, width = "100%" }: { height?: number; width?: string }) {
  return <div className="skeleton" style={{ height, width }} />;
}

export function PolicyCardSkeleton() {
  return (
    <div className="policy-card">
      <div style={{ flex: 1 }}>
        <Skeleton height={15} width="40%" />
        <div style={{ marginTop: 8 }}>
          <Skeleton height={12} width="65%" />
        </div>
      </div>
      <Skeleton height={30} width="90px" />
    </div>
  );
}

export function PolicyFormSkeleton() {
  return (
    <div className="panel">
      <div className="field">
        <Skeleton height={12} width="90px" />
        <Skeleton height={36} />
      </div>
      <div className="field">
        <Skeleton height={12} width="110px" />
        <Skeleton height={36} />
      </div>
      <Skeleton height={70} />
      <div style={{ marginTop: 10 }}>
        <Skeleton height={70} />
      </div>
    </div>
  );
}
