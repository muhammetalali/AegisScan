from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .security import verify_token

bearer = HTTPBearer(auto_error=False)


async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials if credentials else request.cookies.get('aegis_access')
    if not token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    user = await verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid token')
    return user
