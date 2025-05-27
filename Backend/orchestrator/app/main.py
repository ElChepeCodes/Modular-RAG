# orchestrator/app/main.py
from fastapi import FastAPI, HTTPException, Depends
from contextlib import asynccontextmanager
import os
import logging
import httpx
from typing import Dict, Any, List

from agents.common.llm_client import LLMClient # Import the LLMClient
from models.schemas import AgentRegistration, TaskRequest, TaskResponse # Assuming your schema import
from app.intent_entity import IntentEntityRecognizer
from app.config import intent_model_config, entity_patterns_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ier = IntentEntityRecognizer(intent_model_config, entity_patterns_config)

# In-memory storage for registered agents (replace with a more robust solution)
# In a real app, this might be managed by a database or a service discovery tool
registered_agents: Dict[str, str] = {}


# --- FastAPI Application Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic: Initialize LLMClient
    ollama_api_url = os.getenv("OLLAMA_API_URL", "http://ollama:11434")
    # You might want to store this LLMClient instance in app.state or a global variable
    # if it's needed by the orchestrator itself for meta-reasoning.
    # Otherwise, individual agents will create their own LLMClient instances.
    logger.info("FastAPI app startup: LLM Client initialized.")
    yield
    # Shutdown logic: Close httpx client
    await LLMClient.close_httpx_client()
    logger.info("FastAPI app shutdown: LLM Client closed.")


app = FastAPI(lifespan=lifespan) # Link the lifespan to your app


# --- Dependency for LLMClient (if the orchestrator itself needs direct LLM access) ---
# If only agents use LLM, you don't strictly need this in orchestrator's main.py
# unless you also want the orchestrator to have LLM capabilities.
async def get_llm_client():
    ollama_api_url = os.getenv("OLLAMA_API_URL", "http://ollama:11434")
    return LLMClient(ollama_api_base_url=ollama_api_url)


# --- API Endpoints ---

@app.post("/register_agent")
async def register_agent_route(registration: AgentRegistration):
    """Registers a new agent with the orchestrator."""
    if registration.name in registered_agents:
        raise HTTPException(status_code=400, detail=f"Agent '{registration.name}' already registered.")
    registered_agents[registration.name] = registration.url
    logger.info(f"Agent '{registration.name}' registered at '{registration.url}'")
    return {"message": f"Agent '{registration.name}' registered successfully."}

@app.post("/process_query")
async def process_user_query_route(query: str):
    """
    Receives a user query, identifies multiple intents and entities,
    and routes the request to the appropriate agents sequentially.
    """
    intents, entities = ier.recognize_multiple(query)

    if not intents:
        raise HTTPException(status_code=400, detail="Could not identify any intents.")

    results = {}
    previous_output = None

    for intent in intents:
        target_agent_name = intent_model_config.get(intent, {}).get("agent")
        if target_agent_name:
            agent_url = registered_agents.get(target_agent_name)
            if agent_url:
                payload = {"query": query, "intent": intent, "entities": entities, "previous_output": previous_output}
                async with httpx.AsyncClient() as client: # Orchestrator uses httpx client to talk to agent
                    try:
                        response = await client.post(f"{agent_url}/execute", json=payload)
                        response.raise_for_status()
                        current_result = response.json()
                        results[intent] = current_result
                        previous_output = current_result.get("output")
                    except httpx.HTTPError as e:
                        logger.error(f"Error communicating with agent '{target_agent_name}' for intent '{intent}': {e}")
                        results[intent] = {"error": f"Failed to communicate with agent '{target_agent_name}'"}
                        break
            else:
                results[intent] = {"error": f"Agent '{target_agent_name}' not found."}
                break
        else:
            results[intent] = {"error": f"No agent configured for intent '{intent}'."}
            break

    return {"intents": intents, "entities": entities, "results": results}

@app.get("/agents")
async def list_agents():
    """Lists all currently registered agents."""
    return {"agents": list(registered_agents.keys())}


# Example of orchestrator using LLM directly (if needed)
@app.post("/summary")
async def orchestrator_summary_route(
    data_to_summarize: Dict[str, Any],
    llm_client: LLMClient = Depends(get_llm_client) # Inject LLMClient here
):
    """
    Example endpoint where the orchestrator itself uses the LLM client directly.
    """
    prompt = f"Summarize the following data concisely: {data_to_summarize}"
    try:
        summary_response = await llm_client.generate(prompt=prompt, model="llama3")
        return {"summary": summary_response.get("response")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Orchestrator failed to get LLM summary: {e}")

# This part is generally for development
if __name__ == "__main__":
    import uvicorn
    # Set a dummy Ollama URL for local testing if not using Docker Compose
    os.environ["OLLAMA_API_URL"] = "http://localhost:11434"
    uvicorn.run(app, host="0.0.0.0", port=8000)