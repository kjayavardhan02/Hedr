from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models, seed
from app.database import Base, SessionLocal, engine, ensure_schema
from app.routers import auth, dashboard, explain, policies, reports, scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_schema(engine)
    db = SessionLocal()
    try:
        seed.seed_baselines(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Hedr API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(policies.router)
app.include_router(scan.router)
app.include_router(reports.router)
app.include_router(explain.router)
app.include_router(dashboard.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
