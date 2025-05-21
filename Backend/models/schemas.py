from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class AgentRegistration(BaseModel):
    name: str
    url: str
    config: Dict[str, Any]

class TaskRequest(BaseModel):
    agent_name: str
    query: str
    input_data: Dict[str, Any] = {}

class IngestRequest(BaseModel):
    documents: List[str]

class TaskResponse(BaseModel):
    result: str