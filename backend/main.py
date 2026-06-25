# backend/main.py

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests

from backend.simulators import SCENARIOS, generate_live_log
from backend.analyst import analyze_logs, chat_with_analyst

app = FastAPI(title="AI SOC Analyst Assistant")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Configurations Schema
class APIConfig(BaseModel):
    provider: str = "ollama"
    model: str = "llama3"
    api_key: str = ""

# Request schema for custom log analysis
class AnalyzeRequest(BaseModel):
    logs: list
    config: APIConfig = APIConfig()

# Request schema for chat
class ChatRequest(BaseModel):
    context: dict
    message: str
    config: APIConfig = APIConfig()

@app.get("/api/scenarios")
def get_scenarios():
    """
    Get all simulated attack scenarios.
    """
    return [
        {"id": k, "title": v["title"], "description": v["description"], "log_count": len(v["logs"])}
        for k, v in SCENARIOS.items()
    ]

@app.get("/api/scenarios/{scenario_id}")
def get_scenario_details(scenario_id: str):
    """
    Get logs for a specific scenario.
    """
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return SCENARIOS[scenario_id]

@app.post("/api/scenarios/{scenario_id}/analyze")
def analyze_scenario(scenario_id: str, config: APIConfig):
    """
    Run AI analysis on a specific scenario.
    """
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")
    logs = SCENARIOS[scenario_id]["logs"]
    analysis = analyze_logs(logs, config.model_dump())
    return {
        "logs": logs,
        "analysis": analysis
    }

@app.post("/api/analyze-custom")
def analyze_custom(req: AnalyzeRequest):
    """
    Analyze user-provided custom logs.
    """
    if not req.logs:
        raise HTTPException(status_code=400, detail="Log list cannot be empty")
    analysis = analyze_logs(req.logs, req.config.model_dump())
    return {
        "logs": req.logs,
        "analysis": analysis
    }

@app.get("/api/live-stream")
def get_live_stream():
    """
    Generates a single randomized log event.
    """
    return generate_live_log()

@app.post("/api/chat")
def chat(req: ChatRequest):
    """
    Chat with the analyst about the security context.
    """
    response_text = chat_with_analyst(req.context, req.message, req.config.model_dump())
    return {"response": response_text}

@app.post("/api/test-ollama")
def test_ollama(config: APIConfig):
    """
    Test connection to local Ollama.
    """
    try:
        res = requests.get("http://localhost:11434/api/tags", timeout=5)
        if res.status_code == 200:
            models = [m["name"] for m in res.json().get("models", [])]
            status = "connected"
            message = f"Connected to Ollama. Models: {', '.join(models)}"
            if config.model not in models and (config.model + ":latest") not in models:
                message += f" (Warning: Selected model '{config.model}' not found in installed models)"
            return {
                "status": status,
                "message": message,
                "installed_models": models
            }
        return {"status": "error", "message": f"Ollama returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": f"Could not reach Ollama: {str(e)}"}

# Serve Frontend static assets
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend"))

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

# Mount CSS & JS files
app.mount("/", StaticFiles(directory=frontend_dir), name="static")
