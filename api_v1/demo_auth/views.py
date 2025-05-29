import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Header, Response, Cookie
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Annotated, Any
from time import time

router = APIRouter(
    prefix="/demo-auth",
    tags=["Demo Auth"]
)

security = HTTPBasic()

@router.get("/basic-auth/")
def demo_basic_auth_credentials(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
):
    return {
        "message": "Hi",
        "username": credentials.username,
        "password": credentials.password,
    }

usernames_to_passwords = {
    "admin": "admin",
    "john": "password"
}

static_auth_token_to_username = {
    "6cfd4c79e41fbe2b87facf2997b172": "admin",
    "0551a23f03f5508f362425f9c2e0d85494": "john"
}

def get_auth_user_username(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
):
    unauthed_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalide username or password",
        headers={"WWW-Authentificate": "Basic"},
    )

    correct_password = usernames_to_passwords.get(credentials.username)

    if credentials.username not in usernames_to_passwords:
        raise unauthed_exc
    
    if not secrets.compare_digest(
        credentials.password.encode("utf-8"),
        correct_password.encode("utf-8")
    ):
        raise unauthed_exc
    
    return credentials.username

def get_username_by_static_auth_token(
    static_token: str = Header(alias="x-auth-token") 
) -> str:
    if username := static_auth_token_to_username.get(static_token):
        return username
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token"
    )

@router.get("/basic-auth-username/")
def demo_basic_auth_username(
    auth_username: str = Depends(get_auth_user_username),
):
    return {
        "message": f"Hi, {auth_username}",
        "username": auth_username
    }

@router.get("/some-http-header-auth/")
def demo_auth_some_http_header(
    username: str = Depends(get_username_by_static_auth_token),
):
    return {
        "message": f"Hi, {username}",
        "username": username
    }

COOKIES: dict[str, dict[str, Any]] = {}
COOKIE_SESSION_TO_KEY = "web-app-session-id"

def generate_session_id() -> str:
    return uuid.uuid4().hex

def get_session_data(
    session_id: str = Cookie(alias=COOKIE_SESSION_TO_KEY),
):
    if session_id not in COOKIES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authentificated"
        )
    return COOKIES[session_id]

@router.post("/login-cookie/")
def demo_auth_login_cookie(
    response: Response,
    username: str = Depends(get_username_by_static_auth_token),
):
    session_id = generate_session_id()
    COOKIES[session_id] = {
        "username": username,
        "login_at": int(time())
    }
    response.set_cookie(COOKIE_SESSION_TO_KEY, session_id)
    return {"result": "OK"}

@router.get("/check-cookie/")
def demo_auth_check_cookie(
    user_session_data: dict = Depends(get_session_data)
):
    username = user_session_data["username"]
    return {
        "message": f"Hello, {username}",
        **user_session_data
    }

@router.get("/logout-cookie/")
def demo_logout_cookie(
    response: Response,
    session_id: str = Cookie(alias=COOKIE_SESSION_TO_KEY),
    user_session_data: dict = Depends(get_session_data)
):
    COOKIES.pop(session_id)
    response.delete_cookie(COOKIE_SESSION_TO_KEY)
    username = user_session_data["username"]
    return {
        "message": f"Bye, {username}"
    }