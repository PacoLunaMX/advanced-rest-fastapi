import datetime
import logging
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from api.config import config
from api.database import database, user_table

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"])


def credentials_exception(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def access_token_expire_minutes() -> int:
    return 30


def confirmation_token_expire_minutes() -> int:
    return 1440


def create_access_token(email: str):
    logger.debug("Creating access token", extra={"email": email})

    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=EXPIRE_MINUTES
    )
    jwt_data = {"sub": email, "exp": access_token_expire_minutes, "type": "access"}
    encoded_jwt = jwt.encode(jwt_data, config.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_confirmation_token(email: str):
    logger.debug("Creating confirmation token", extra={"email": email})

    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=EXPIRE_MINUTES
    )
    jwt_data = {
        "sub": email,
        "exp": confirmation_token_expire_minutes,
        "type": "confirmation",
    }
    encoded_jwt = jwt.encode(jwt_data, config.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_subject_for_token_type(
    token: str, type: Literal["access", "confirmation"]
) -> str:
    try:
        payload = jwt.decode(token, key=config.SECRET_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError as e:
        raise credentials_exception("Token has expire") from e

    except JWTError as e:
        raise credentials_exception("Invalid token") from e

    email = payload.get("sub")
    if email is None:
        raise credentials_exception("Token is missing 'sub' field")

    token_type = payload.get("type")
    if token_type is None or token_type != type:
        raise credentials_exception(f"Token has incorrect type, expected {type}")

    return email


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


async def get_user(email: str):
    logger.debug("Fetching user from the databse", extra={"email": email})
    query = user_table.select().where(user_table.c.email == email)
    result = await database.fetch_one(query)
    if result:
        return result


async def authenticate_user(email: str, password: str):
    logger.debug("Authenticating user", extra={"emal": email})

    user = await get_user(email)
    if not user:
        raise credentials_exception("Invalid email or password")
    if not verify_password(password, user.password):
        raise credentials_exception("Invalid email or password")
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    email = get_subject_for_token_type(token, "access")
    user = await get_user(email=email)
    if user is None:
        raise credentials_exception("Could not find user for this token")

    return user
