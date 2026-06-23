from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import analyze

app = FastAPI(
    title="Threat Intelligence Platform",
    version="1.0.0",
    description="AI-powered threat intelligence and attack mapping platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)


@app.get("/")
async def root():
    return {
        "status": "healthy",
        "service": "Threat Intelligence Platform",
        "message": "Backend is running"
    }


@app.get("/health")
async def health_check():
    return {
        "status": "ok"
    }