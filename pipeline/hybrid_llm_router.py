"""
Hybrid LLM Router: routes prompts to cloud or local models based on task type.

Supported providers:
  - fugu (Sakana Fugu AI — multi-agent orchestration model, matches Claude Sonnet 4 / GPT-5)
  - openrouter (OpenRouter API, fallback for non-Fugu tasks)
  - lmstudio (local, OpenAI-compatible endpoint)
  - openai (OpenAI API, for direct GPT-4/5 access)

Usage:
    router = HybridLLMRouter(config_path="config.yaml")
    response = await router.route(task_type="complex_evasion", prompt=prompt)
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

# --- LLM Provider Abstractions ---

def _chat_completion(provider: str, endpoint: str, model: str, messages: list[dict], **kwargs) -> str:
    """Unified chat completion interface for all providers."""
    
    if provider == "fugu":
        return _fugu_chat(endpoint, model, messages, kwargs)
    elif provider == "lmstudio":
        return _lmstudio_chat(endpoint, model, messages, kwargs)
    elif provider == "openai":
        return _openai_chat(endpoint or "https://api.openai.com/v1", model, messages, kwargs)
    elif provider == "openrouter":
        return _openrouter_chat(endpoint or "https://api.openrouter.ai/api/v1", model, messages, kwargs)
    else:
        raise ValueError(f"Unknown provider: {provider}")


def _lmstudio_chat(endpoint: str, model: str, messages: list[dict], kwargs: dict) -> str:
    """Send chat completion to local LM Studio endpoint."""
    import httpx
    
    url = endpoint.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    
    payload = {
        "model": model,
        "messages": messages,
        **kwargs,
    }
    
    with httpx.Client(timeout=300.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def _openai_chat(base_url: str, model: str, messages: list[dict], kwargs: dict) -> str:
    """Send chat completion to OpenAI-compatible endpoint."""
    import httpx
    
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}",
    }
    
    payload = {"model": model, "messages": messages, **kwargs}
    
    with httpx.Client(timeout=300.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def _openrouter_chat(base_url: str, model: str, messages: list[dict], kwargs: dict) -> str:
    """Send chat completion to OpenRouter."""
    import httpx
    
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY', '')}",
        "HTTP-Referer": "https://github.com/malware_gen_framework",
        "X-Title": "MalGen Framework",
    }
    
    payload = {"model": model, "messages": messages, **kwargs}
    
    with httpx.Client(timeout=300.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def _fugu_chat(base_url: str, model: str, messages: list[dict], kwargs: dict) -> str:
    """Send chat completion to Sakana Fugu AI API."""
    import httpx
    
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ.get('FUGU_API_KEY', '')}",
    }
    
    payload = {"model": model, "messages": messages, **kwargs}
    
    with httpx.Client(timeout=300.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


# --- Task Type Classification ---

TASK_ROUTING = {
    "design":             {"provider": "fugu",      "model": None},         # multi-agent orchestration excels at architecture planning
    "component_generate":  {"provider": "lmstudio",   "model": None},       # generates code — stays local for speed/cost
    "assembly":           {"provider": "lmstudio",   "model": None},       # deterministic, low creativity needed
    "optimization":       {"provider": "lmstudio",   "model": None},       # reads own code, local is fine
}

# Cloud tasks (Fugu): reasoning-only, no generated code — won't trigger guardrails
# component_generate / assembly / optimization stay local for cost + latency

DEFAULT_ROUTING = {
    "default_provider": "lmstudio",
    "complex_threshold": 0.7,  # if complexity score > this, use cloud
}


@dataclass
class LLMConfig:
    """Configuration for hybrid LLM routing."""
    
    # Cloud providers
    openrouter_api_key: str = ""
    openai_api_key: str = ""
    fugu_api_key: str = ""  # Sakana Fugu AI API key — env var: FUGU_API_KEY
    openrouter_base_url: str = "https://api.openrouter.ai/api/v1"
    openai_base_url: str = "https://api.openai.com/v1"
    
    # Local provider (LM Studio) — defaults from environment
    lmstudio_endpoint: str = ""  # env var: LM_STUDIO_ENDPOINT
    local_model_name: str = ""  # env var: LOCAL_MODEL_NAME
    
    # Defaults
    strategy: str = "hybrid"  # "cloud" | "local" | "hybrid"

    def __post_init__(self):
        """Apply environment variable overrides for all fields."""
        
        self.openrouter_api_key = os.environ.get("OPENROUTER_API_KEY", self.openrouter_api_key)
        self.openai_api_key = os.environ.get("OPENAI_API_KEY", self.openai_api_key)
        self.fugu_api_key = os.environ.get("FUGU_API_KEY", self.fugu_api_key)
        
        lmstudio_endpoint = os.environ.get("LM_STUDIO_ENDPOINT", "")
        if lmstudio_endpoint:
            self.lmstudio_endpoint = lmstudio_endpoint
        
        local_model_name = os.environ.get("LOCAL_MODEL_NAME", "")
        if local_model_name:
            self.local_model_name = local_model_name
    
    def get_config(self, task_type: str) -> dict:
        """Get routing config for a specific task type."""
        
        # Hybrid mode: use per-task-type routing from TASK_ROUTING
        if self.strategy == "hybrid" and task_type in TASK_ROUTING:
            route = TASK_ROUTING[task_type]
            provider = route["provider"]
            
            # Determine base URL for the provider
            base_url_attr = f"{provider}_base_url"
            base_url = getattr(self, base_url_attr, None) or ""
            
            return {
                "provider": provider,
                "model": route.get("model") or "",
                "base_url": base_url if provider != "lmstudio" else self.lmstudio_endpoint,
            }
        
        # Cloud-only strategy: use openrouter by default
        elif self.strategy == "cloud":
            return {
                "provider": "openrouter",
                "model": "anthropic/claude-sonnet-4",
                "base_url": self.openrouter_base_url,
            }
        
        # Local-only strategy or fallback: use LM Studio
        else:
            return {
                "provider": "lmstudio",
                "model": self.local_model_name,
                "endpoint": self.lmstudio_endpoint,
            }


class HybridLLMRouter:
    """Routes prompts to appropriate LLM based on task type."""
    
    def __init__(self, config: Optional[LLMConfig] = None):
        if config is None:
            config = LLMConfig()
        self.config = config
    
    def route(self, task_type: str, prompt: str, system_prompt: str = "", 
              **kwargs) -> dict[str, Any]:
        """Route a prompt to the appropriate model.
        
        Args:
            task_type: One of the predefined task types (design, complex_evasion, etc.)
            prompt: The user prompt text
            system_prompt: System message for the LLM
            **kwargs: Additional parameters forwarded to the chat completion API
            
        Returns:
            dict with keys: {"response": str, "provider": str, "model": str}
        """
        
        route_config = self.config.get_config(task_type)
        provider = route_config["provider"]
        model_name = route_config.get("model") or self.config.local_model_name
        
        # Build messages
        messages: list[dict] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        # For complex_evasion and design, include structured context
        if task_type in ("design", "complex_evasion"):
            messages.extend(kwargs.pop("messages", [{"role": "user", "content": prompt}]))
        else:
            messages.append({"role": "user", "content": prompt})
        
        # Default temperature settings by task type
        defaults = {
            "design": {"temperature": 0.3, "max_tokens": 2048},
            "complex_evasion": {"temperature": 0.5, "max_tokens": 3072},
            "edr_retry": {"temperature": 0.3, "max_tokens": 2048},
            "component_generate": {"temperature": 0.4, "max_tokens": 16384},
            "assembly": {"temperature": 0.2, "max_tokens": 4096},
            "optimization": {"temperature": 0.3, "max_tokens": 4096},
        }
        
        api_kwargs = {**defaults.get(task_type, {}), **kwargs}
        
        # Execute the chat completion
        response_text = _chat_completion(
            provider=provider,
            endpoint=route_config.get("endpoint") or route_config.get("base_url", ""),
            model=model_name,
            messages=messages,
            **api_kwargs,
        )
        
        return {
            "response": response_text,
            "provider": provider,
            "model": model_name,
        }
