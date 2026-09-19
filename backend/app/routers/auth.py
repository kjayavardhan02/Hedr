from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app import models
from app.config import COOKIE_SECURE, JWT_EXPIRE_MINUTES, SESSION_COOKIE_NAME
from app.core.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password_or_dummy
from app.database import get_db
from app.schemas import UserCreate, UserLogin, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _set_session_cookie(response: Response, user_id: str) -> None:
    token = create_access_token(user_id=user_id)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=JWT_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserCreate, response: Response, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    existing = db.query(models.User).filter(models.User.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user = models.User(
        email=email,
        hashed_password=hash_password(payload.password),
        first_name=payload.first_name,
        last_name=payload.last_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    _set_session_cookie(response, user.id)
    return user


@router.post("/login", response_model=UserOut)
def login(payload: UserLogin, response: Response, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(models.User).filter(models.User.email == email).first()

    # Always run a bcrypt comparison, even when the email isn't found, so a
    # response-timing difference can't be used to enumerate registered
    # emails. The error message is identical either way for the same reason.
    ok = verify_password_or_dummy(payload.password, user.hashed_password if user else None)
    if not user or not ok:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    _set_session_cookie(response, user.id)
    return user


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"detail": "Logged out."}


@router.get("/me", response_model=UserOut)
def me(current_user: models.User = Depends(get_current_user)):
    return current_user
