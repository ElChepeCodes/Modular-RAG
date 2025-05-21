from abc import ABC, abstractmethod
from typing import Any, Dict

class IAgent(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def initialize(self, config: Dict[str, Any]):
        """
        Initialize the agent.
        """
        raise NotImplementedError("This method should be overridden by subclasses.")

    @abstractmethod
    def execute(self, query: str, context: str = None):
        """
        Execute a command using the agent.
        """
        raise NotImplementedError("This method should be overridden by subclasses.")
    
    @abstractmethod
    def health_check(self):
        """
        Check the health of the agent.
        """
        raise NotImplementedError("This method should be overridden by subclasses.")