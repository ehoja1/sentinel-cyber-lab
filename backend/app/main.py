from fastapi import FastAPI
from pydantic import BaseModel, Field

from backend.app.analyzer import analyze_logs


app = FastAPI(
    title="SENTINEL Cyber Lab",
    description=(
        "API local para análise defensiva de eventos de segurança."
    ),
    version="0.2.0",
)


@app.get("/")
def root():
    return {
        "name": "SENTINEL Cyber Lab",
        "version": "0.2.0",
        "status": "online",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


class LogRequest(BaseModel):
    text: str
    brute_force_threshold: int = Field(default=5, ge=1)


@app.post("/analyze")
def analyze(request: LogRequest):
    return analyze_logs(
        request.text,
        brute_force_threshold=request.brute_force_threshold,
    )
