from fastapi import (
    APIRouter, 
    Depends, 
    Form, 
    HTTPException,
    status
)
from fastapi.security import (
    HTTPBearer, 
    HTTPAuthorizationCredentials,
    OAuth2PasswordBearer,
)
from pydantic import BaseModel
from jwt.exceptions import InvalidTokenError

from users.schemas import UserSchema
from auth import utils as auth_utils
from api_v1.demo_auth.helpers import (
    create_access_token, 
    create_refresh_token,
)
from api_v1.demo_auth.validation import (
    get_current_token_payload,
    get_current_auth_user,
    get_current_auth_user_for_refresh,
)

http_beader = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/demo-auth/jwt/login/",
)

class TokenInfo(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"

router = APIRouter(
    prefix="/jwt", 
    tags=["JWT"],
    dependencies=[Depends(http_beader)],
)

john = UserSchema(
    username="john",
    password=auth_utils.hash_password("qwerty"),
    email="john@example.com",
)

sam = UserSchema(
    username="sam",
    password=auth_utils.hash_password("secret"),
)

users_db: dict[str, UserSchema] = {
    john.username: john,
    sam.username: sam,
}

def validate_auth_user(
    username: str = Form(),
    password: str = Form(),
):
    unauthed_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password"
    )

    if not (user := users_db.get(username)):
        raise unauthed_exc
    
    if auth_utils.validate_password(
        password=password,
        hashed_password=user.password,
    ):
        return user
    
    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User inactive",
        )

    raise unauthed_exc

def get_current_active_auth_user(
    user: UserSchema = Depends(get_current_auth_user)  
): 
    if user.active:
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="user inactive"
    )

@router.post("/login/", response_model=TokenInfo)
async def auth_user_issue_jwt(
    user: UserSchema = Depends(validate_auth_user),
):
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    return TokenInfo(
        access_token=access_token,
        refresh_token=refresh_token,
    )

@router.post(
        "/refresh/", 
        response_model=TokenInfo,
        response_model_exclude_none=True,
)
def auth_refresh_jwt(
    user: UserSchema = Depends(get_current_auth_user_for_refresh)
):
    access_token = create_access_token(user)
    return TokenInfo(
        access_token=access_token,
    )

@router.get("/users/me/")
def auth_user_check_self_info(
    payload: dict = Depends(get_current_token_payload),
    user: UserSchema = Depends(get_current_active_auth_user),
):
    iat = payload.get("iat")
    return {
        "username": user.username,
        "email": user.email,
        "logged_in_at": iat,
    }