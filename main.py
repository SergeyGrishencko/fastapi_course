import uvicorn

from fastapi import FastAPI
from contextlib import asynccontextmanager

from core.config import settings
from core.models import Base, db_helper
from api_v1 import router as router_v1
from items_views import router as items_router
from users.views import router as user_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(router=router_v1, prefix=settings.api_v1_prefix)
app.include_router(items_router)
app.include_router(user_router)

@app.get("/")
def hello_index():
    return {
        "message": "Hello, index!"
    }

@app.get("/hello/")
def hello(name: str):
    name = name.strip().title()
    return {"message": f"Hello, {name}"}

@app.get("/calc/add/")
def add(a: int, b: int):
    return {
        "a": a,
        "b": b,
        "result": a + b
    }

if __name__ == '__main__':
    uvicorn.run("main:app", reload=True)