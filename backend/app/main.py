from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models, seed
from app.database import Base, SessionLocal, engine
from app.routers import explain, policies, scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
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

app.include_router(policies.router)
app.include_router(scan.router)
app.include_router(explain.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
