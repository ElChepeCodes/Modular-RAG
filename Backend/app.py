from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict

from llm import OpenAIAgent, OllamaAgent
from orchestrator import Orchestrator
app = FastAPI()
orchestrator = Orchestrator("http://localhost:6333")

class QueryRequest(BaseModel):
    text: str
    agent: str
    params: Dict = {}

@app.post("/init")
def initialize_agents():
    # Initialize agents
    orchestrator.register_agent(
        "openai",
        OpenAIAgent(),
        {"api_key": "your-openai-key"}
    )
    orchestrator.register_agent(
        "ollama",
        OllamaAgent(),
        {"base_url": "http://localhost:11434"}
    )
    return {"status": "initialized"}

@app.post("/query")
async def handle_query(request: QueryRequest):
    try:
        result = orchestrator.process_query(
            request.text,
            request.agent
        )
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)