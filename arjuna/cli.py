"""Interactive Rich-based Terminal User Interface for Arjuna."""

from __future__ import annotations

import sys
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from arjuna.config import settings
from arjuna.memory import MemoryStore
from arjuna.ollama_client import OllamaClient
from arjuna.tools import ToolRegistry


class ArjunaCLI:
    """Terminal chat interface for Arjuna."""

    def __init__(self) -> None:
        self.console = Console()
        self.memory = MemoryStore(settings.db_path)
        self.client = OllamaClient()
        self.tools = ToolRegistry(self.memory)
        self.conversation_id = self.memory.get_or_create_conversation()
        self.show_thinking = settings.show_thinking

    def display_banner(self) -> None:
        """Render welcoming startup banner."""
        banner_text = Text()
        banner_text.append("🏹 ARJUNA ", style="bold gold1")
        banner_text.append("— Local-First Zero-Cost AI Assistant\n", style="bold white")
        banner_text.append("Runtime: ", style="dim")
        banner_text.append("Ollama (Local)  ", style="green")
        banner_text.append("Model: ", style="dim")
        banner_text.append(f"{settings.model}  ", style="cyan")
        banner_text.append("VRAM: ", style="dim")
        banner_text.append("NVIDIA MX450 (CUDA)  ", style="magenta")
        banner_text.append("Cost: ", style="dim")
        banner_text.append("₹0.00 (100% Free & Private)\n", style="bold green")
        banner_text.append("Commands: ", style="dim")
        banner_text.append("/help, /status, /think, /new, /memories, /exit", style="italic yellow")

        panel = Panel(
            banner_text,
            title="[bold blue]System Ready[/bold blue]",
            border_style="bright_blue",
            padding=(0, 2),
        )
        self.console.print(panel)

    def handle_command(self, cmd: str) -> bool:
        """Process slash commands. Returns True if handled."""
        parts = cmd.strip().split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if command in ("/exit", "/quit", "/q"):
            self.console.print("[bold yellow]Exiting Arjuna. Good luck![/bold yellow]")
            sys.exit(0)

        elif command == "/help":
            table = Table(title="Arjuna Commands", border_style="dim")
            table.add_column("Command", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_row("/help", "Show this command summary")
            table.add_row("/status", "Display live GPU, RAM, and hardware metrics")
            table.add_row("/think", f"Toggle internal reasoning display (Currently: {'ON' if self.show_thinking else 'OFF'})")
            table.add_row("/new", "Start a clean conversation thread")
            table.add_row("/history", "Display current session messages")
            table.add_row("/memories", "List all persistent facts stored in SQLite")
            table.add_row("/remember <k> = <v>", "Save persistent fact (e.g. /remember project = Arjuna)")
            table.add_row("/forget <key>", "Delete a saved fact")
            table.add_row("/models", "List models installed in local Ollama")
            table.add_row("/clear", "Clear terminal screen")
            table.add_row("/exit", "Close application")
            self.console.print(table)
            return True

        elif command == "/status":
            status = self.tools.get_system_status()
            panel = Panel(
                f"[bold cyan]OS:[/bold cyan] {status['os']}\n"
                f"[bold cyan]Time:[/bold cyan] {status['time']}\n"
                f"[bold cyan]GPU:[/bold cyan] {status['gpu_info']}\n"
                f"[bold cyan]RAM Info:[/bold cyan]\n{status['ram_info']}",
                title="Hardware Diagnostics",
                border_style="cyan",
            )
            self.console.print(panel)
            return True

        elif command == "/think":
            self.show_thinking = not self.show_thinking
            state = "[bold green]ENABLED[/bold green]" if self.show_thinking else "[bold red]DISABLED[/bold red]"
            self.console.print(f"Hybrid reasoning display is now {state}.")
            return True

        elif command == "/new":
            self.conversation_id = self.memory.create_conversation("New Conversation")
            self.console.print(f"[bold green]Created new conversation session: {self.conversation_id}[/bold green]")
            return True

        elif command == "/history":
            history = self.memory.get_history(self.conversation_id)
            if not history:
                self.console.print("[dim]No messages in current conversation.[/dim]")
            for msg in history:
                color = "green" if msg["role"] == "user" else "cyan"
                self.console.print(f"[bold {color}]{msg['role'].upper()}:[/bold {color}] {msg['content']}")
            return True

        elif command == "/memories":
            facts = self.memory.list_facts()
            if not facts:
                self.console.print("[dim]No persistent facts stored in memory yet. Use /remember key = value[/dim]")
            else:
                table = Table(title="Persistent Facts", border_style="gold1")
                table.add_column("Key", style="bold gold1")
                table.add_column("Value", style="white")
                for k, v in facts.items():
                    table.add_row(k, v)
                self.console.print(table)
            return True

        elif command == "/remember":
            if "=" in arg:
                k, v = arg.split("=", 1)
                res = self.tools.remember(k.strip(), v.strip())
                self.console.print(f"[green]{res}[/green]")
            else:
                self.console.print("[red]Usage: /remember <key> = <value>[/red]")
            return True

        elif command == "/forget":
            if arg:
                deleted = self.memory.delete_fact(arg.strip())
                if deleted:
                    self.console.print(f"[yellow]Deleted fact '{arg.strip()}'.[/yellow]")
                else:
                    self.console.print(f"[red]Fact '{arg.strip()}' not found.[/red]")
            else:
                self.console.print("[red]Usage: /forget <key>[/red]")
            return True

        elif command == "/models":
            models = self.client.list_models()
            table = Table(title="Installed Ollama Models", border_style="green")
            table.add_column("Model Name", style="bold green")
            table.add_column("Size (GB)", style="cyan")
            table.add_column("Family", style="magenta")
            for m in models:
                size_gb = round(m.get("size", 0) / (1024**3), 2)
                family = m.get("details", {}).get("family", "unknown")
                table.add_row(m.get("name", "unknown"), str(size_gb), family)
            self.console.print(table)
            return True

        elif command == "/clear":
            self.console.clear()
            self.display_banner()
            return True

        return False

    def run(self) -> None:
        """Start the interactive loop."""
        self.display_banner()

        if not self.client.is_alive():
            self.console.print(
                "[bold red]Warning: Local Ollama service is not reachable at "
                f"{settings.ollama_host}.[/bold red]\n"
                "[dim]Make sure 'ollama serve' is running.[/dim]\n"
            )

        while True:
            try:
                user_input = self.console.input("\n[bold green]You > [/bold green]").strip()
                if not user_input:
                    continue

                if user_input.startswith("/"):
                    if self.handle_command(user_input):
                        continue

                # Prepare context: include relevant facts in system instruction
                facts = self.memory.list_facts()
                facts_str = ""
                if facts:
                    facts_lines = [f"- {k}: {v}" for k, v in facts.items()]
                    facts_str = "\nKnown user facts:\n" + "\n".join(facts_lines)

                effective_system = settings.system_prompt + facts_str

                # Build recent chat history
                recent_history = self.memory.get_history(self.conversation_id, limit=10)
                messages = [{"role": m["role"], "content": m["content"]} for m in recent_history]
                messages.append({"role": "user", "content": user_input})

                # Stream response
                self.console.print("[bold cyan]Arjuna > [/bold cyan]", end="")
                thinking_tokens: list[str] = []
                content_tokens: list[str] = []
                think_printed = False

                for chunk in self.client.chat_stream(messages, system=effective_system):
                    token = chunk["token"]
                    if chunk["in_think"]:
                        thinking_tokens.append(token)
                        if self.show_thinking:
                            if not think_printed:
                                self.console.print("\n[dim cyan]Thinking...[/dim cyan]")
                                think_printed = True
                            self.console.print(f"[dim]{token}[/dim]", end="")
                    else:
                        if think_printed and not content_tokens:
                            self.console.print("\n\n[bold cyan]Arjuna > [/bold cyan]", end="")
                            think_printed = False
                        content_tokens.append(token)
                        self.console.print(token, end="")

                self.console.print()  # newline

                full_content = "".join(content_tokens).strip()
                full_thinking = "".join(thinking_tokens).strip()

                # Persist both user and assistant messages
                self.memory.add_message(self.conversation_id, "user", user_input)
                self.memory.add_message(
                    self.conversation_id,
                    "assistant",
                    full_content,
                    thinking=full_thinking,
                )

            except KeyboardInterrupt:
                self.console.print("\n[dim]Interrupted. Type /exit to quit.[/dim]")
            except Exception as e:
                self.console.print(f"\n[bold red]Error:[/bold red] {e}")


def main() -> None:
    """Entrypoint function."""
    cli = ArjunaCLI()
    cli.run()


if __name__ == "__main__":
    main()
