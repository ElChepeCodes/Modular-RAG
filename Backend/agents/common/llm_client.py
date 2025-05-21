# Backend/agents/common/llm_client.py
import os
import httpx
import logging
import json
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class LLMClient:
    """
    A client for interacting with the Ollama LLM provider.
    Uses a shared httpx.AsyncClient for efficiency.
    """
    _httpx_client: Optional[httpx.AsyncClient] = None

    def __init__(self, ollama_api_base_url: str = "http://localhost:11434"):
        self.ollama_api_base_url = ollama_api_base_url.rstrip('/')
        if LLMClient._httpx_client is None:
            LLMClient._httpx_client = httpx.AsyncClient(timeout=60.0)

    @classmethod
    async def close_httpx_client(cls):
        """Closes the shared httpx client."""
        if cls._httpx_client:
            await cls._httpx_client.aclose()
            cls._httpx_client = None

    async def generate(
        self,
        prompt: str,
        model: str = os.environ.get("MODEL_NAME", ""),
        system_message: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
        stream: bool = False,
        **kwargs  # Allow passing additional Ollama API parameters
    ) -> Dict[str, Any]:
        """
        Sends a generation request to the Ollama LLM API's /api/chat endpoint.
        """
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})

        request_data = {
            "model": model,
            "messages": messages,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                **kwargs
            },
            "stream": stream
        }

        try:
            response = await self._httpx_client.post(  # Use the shared client
                f"{self.ollama_api_base_url}/api/chat", json=request_data
            )
            response.raise_for_status()

            if stream:
                full_response_content = []
                async for chunk in response.aiter_bytes():
                    try:
                        chunk_str = chunk.decode('utf-8')
                        for line in chunk_str.strip().split('\n'):
                            if line:
                                json_data = json.loads(line)
                                if "message" in json_data and "content" in json_data["message"]:
                                    full_response_content.append(json_data["message"]["content"])
                    except json.JSONDecodeError as e:
                        logger.warning(f"JSON decode error in streaming response: {e} - Chunk: {chunk_str[:100]}...")
                return {"response": "".join(full_response_content)}
            else:
                return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"LLM API HTTP error {e.response.status_code}: {e.response.text}")
            raise RuntimeError(f"LLM API error: {e.response.text}") from e
        except httpx.RequestError as e:
            logger.error(f"Network error communicating with LLM API at {self.ollama_api_base_url}: {e}")
            raise RuntimeError(f"Network error contacting LLM: {e}") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred during LLM API call: {e}")
            raise RuntimeError(f"Unexpected LLM call error: {e}") from e

# You might also want to expose a simple generate method for simpler cases
# This can be handled by the agent directly constructing the prompt.