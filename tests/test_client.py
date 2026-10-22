"""Unit tests for Ollama client connectivity and models."""

from arjuna.ollama_client import OllamaClient


def test_ollama_client_is_alive():
    client = OllamaClient()
    assert client.is_alive() is True


def test_ollama_list_models():
    client = OllamaClient()
    models = client.list_models()
    assert isinstance(models, list)
    model_names = [m.get("name") for m in models]
    assert any("minicpm5" in name for name in model_names if name)
