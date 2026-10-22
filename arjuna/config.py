"""Configuration management for Arjuna."""

from pathlib import Path
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Runtime configuration settings."""

    # Ollama Service
    ollama_host: str = Field(
        default="http://127.0.0.1:11434",
        description="Local Ollama server HTTP address.",
    )
    model: str = Field(
        default="minicpm5:1b",
        description="Active Ollama model identifier.",
    )
    context_length: int = Field(
        default=4096,
        description="Maximum context window size (safe for 2GB VRAM).",
    )
    temperature: float = Field(
        default=0.7,
        description="Generation temperature.",
    )
    top_p: float = Field(
        default=0.95,
        description="Top-p nucleus sampling probability.",
    )

    # Storage
    data_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent,
        description="Base project data directory.",
    )
    db_name: str = Field(
        default="arjuna.db",
        description="SQLite database filename.",
    )

    # Behavior
    show_thinking: bool = Field(
        default=True,
        description="Display internal hybrid reasoning block (<think> tags).",
    )
    stream: bool = Field(
        default=True,
        description="Stream generation tokens live to the console.",
    )
    system_prompt: str = Field(
        default=(
            "You are Arjuna, a sharp, focused, local-first AI assistant. "
            "You run completely offline and private on local hardware with zero external API fees. "
            "Deliver accurate, helpful, and concise responses. Use tools when appropriate."
        ),
        description="Default system instruction.",
    )

    @property
    def db_path(self) -> Path:
        """Absolute path to the SQLite memory database."""
        return self.data_dir / self.db_name


# Global default settings instance
settings = Settings()
