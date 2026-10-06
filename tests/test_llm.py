import os
from unittest.mock import patch
import app.llm as llm

def test_gemini_enabled(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    monkeypatch.setenv("LLM_ENABLED", "true")
    assert llm.enabled() is True

def test_gemini_model_instantiation(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    
    # Clear lru_cache for _model
    llm._model.cache_clear()
    
    model = llm._model()
    assert model.model == "gemini-3.8-flash"
    assert model.google_api_key.get_secret_value() == "test-key-123"
    
    llm._model.cache_clear()
