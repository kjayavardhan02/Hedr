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

export function DashboardSkeleton() {
  return (
    <>
      <div className="panel">
        <Skeleton height={22} width="220px" />
        <div style={{ marginTop: 8 }}>
          <Skeleton height={13} width="60%" />
        </div>
      </div>
      <div className="row" style={{ marginTop: 16 }}>
        {[0, 1, 2, 3].map((i) => (
          <div className="panel" style={{ flex: "1 1 200px" }} key={i}>
            <Skeleton height={12} width="70px" />
            <div style={{ marginTop: 8 }}>
              <Skeleton height={26} width="50px" />
            </div>
          </div>
        ))}
      </div>
      <div className="panel" style={{ marginTop: 16 }}>
        <Skeleton height={110} />
      </div>
      <div className="panel" style={{ marginTop: 16 }}>
        <PolicyCardSkeleton />
        <PolicyCardSkeleton />
      </div>
    </>
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
