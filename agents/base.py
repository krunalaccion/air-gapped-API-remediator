"""
Base definitions and registry for the Multi-Agent System.
All specialized subagents implement the BaseAgent interface to enable seamless
orchestration and unified monitoring via the common Web UI.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("agents.base")


class BaseAgent(ABC):
    """
    Abstract base class for all specialist agents in the multi-agent ecosystem.
    Provides standard lifecycle hooks, status reporting, and execution interfaces.
    """

    def __init__(self, name: str, role: str, description: str = ""):
        self.name = name
        self.role = role
        self.description = description
        self.status: str = "READY"
        self.last_result: Optional[Dict[str, Any]] = None

    @abstractmethod
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent's core task against the shared workspace/context.

        Args:
            context: Shared dictionary containing workspace paths, configuration,
                     and artifacts from upstream agents.

        Returns:
            Dictionary containing the task results and any generated artifacts.
        """
        pass

    def get_info(self) -> Dict[str, Any]:
        """Returns metadata for the common web dashboard and orchestrator."""
        return {
            "name": self.name,
            "role": self.role,
            "description": self.description,
            "status": self.status,
            "has_result": self.last_result is not None,
        }


class AgentRegistry:
    """
    Central registry for discovering, inspecting, and executing agents.
    Enables the common Web UI to dynamically display connected agents.
    """

    _agents: Dict[str, BaseAgent] = {}

    @classmethod
    def register(cls, agent_id: str, agent: BaseAgent) -> None:
        """Register an agent instance by unique identifier."""
        cls._agents[agent_id] = agent
        logger.info("Registered agent [%s]: %s (%s)", agent_id, agent.name, agent.role)

    @classmethod
    def get(cls, agent_id: str) -> Optional[BaseAgent]:
        """Retrieve an agent by identifier."""
        return cls._agents.get(agent_id)

    @classmethod
    def list_agents(cls) -> List[Dict[str, Any]]:
        """List all registered agents and their current statuses."""
        return [
            {"id": agent_id, **agent.get_info()}
            for agent_id, agent in cls._agents.items()
        ]

    @classmethod
    def clear(cls) -> None:
        """Clear registry (primarily for test isolation)."""
        cls._agents.clear()

