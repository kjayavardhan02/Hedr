import json
from pathlib import Path

from sqlalchemy.orm import Session

from app import models

BASELINES_DIR = Path(__file__).parent / "baselines"


def seed_baselines(db: Session) -> None:
    for path in sorted(BASELINES_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        existing = (
            db.query(models.Policy)
            .filter(models.Policy.baseline_key == data["key"])
            .first()
        )
        if existing:
            # Keep baseline definitions in sync with the checked-in files.
            existing.name = data["name"]
            existing.description = data["description"]
            existing.headers = data["headers"]
            existing.is_baseline = True
        else:
            db.add(
                models.Policy(
                    name=data["name"],
                    description=data["description"],
                    headers=data["headers"],
                    is_baseline=True,
                    baseline_key=data["key"],
                )
            )
    db.commit()
