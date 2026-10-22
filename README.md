# 🏹 Arjuna: Zero-Budget, Local-First AI Assistant

Arjuna is a fully private, zero-cost, local-first AI assistant engineered to run efficiently on low-resource hardware (such as 8 GB RAM laptops with 2 GB entry-level NVIDIA GPUs).

Powered by **Ollama**, **MiniCPM5-1B (Q4_K_M)**, **SQLite**, and Python, Arjuna requires **₹0 in API fees**, no subscriptions, and works 100% offline.

---

## ⚡ Verified Hardware & Performance Benchmarks

*Benchmarked live on Windows 11 with an Intel Core i5-1135G7 and NVIDIA GeForce MX450 (2 GB VRAM):*

| Metric | Measured Value | Notes |
|---|---|---|
| **Inference Engine** | Ollama 0.33.3 + CUDA 13.1 | Discrete GPU acceleration enabled |
| **Model** | `minicpm5:1b` (Q4_K_M) | 1.08B params, hybrid `<think>` reasoning |
| **Disk Storage** | 688 MB in `D:\ollama-models` | Models stored safely off system drive |
| **Active VRAM Usage** | **~597 MiB** / 2,048 MiB | Leaves >1.3 GB VRAM free |
| **Cold-Start Time** | ~58s | Full buffer allocation & CUDA warmup |
| **Warm Generation Speed** | **41.5 tokens/second** | Fluid interactive experience |
| **Cost** | **₹0.00** | 100% free and open-source |

---

## 🚀 Key Features

- **Hybrid Chain-of-Thought Reasoning**: MiniCPM5 natively supports `<think>` reasoning blocks. You can view or toggle the thought process live via `/think`.
- **Persistent SQLite Memory**: Stores full conversation sessions and cross-session user facts (`/remember key = value`).
- **Context-Restricted Execution**: Default 4,096-token context window prevents VRAM exhaustion on 2 GB graphics cards.
- **Rich Terminal Interface**: Live streaming with syntax highlighting, diagnostics panels, and session management.
- **Local Diagnostics**: Built-in `/status` command monitors real-time RAM, GPU VRAM, and system health.

---

## 🛠️ Quick Start

### 1. Prerequisites
Ensure Ollama is installed and running with CUDA acceleration:
```powershell
# Set persistent user environment variables
[System.Environment]::SetEnvironmentVariable('OLLAMA_MODELS', 'D:\ollama-models', 'User')
[System.Environment]::SetEnvironmentVariable('OLLAMA_LLM_LIBRARY', 'cuda_v13', 'User')
[System.Environment]::SetEnvironmentVariable('OLLAMA_FLASH_ATTENTION', '1', 'User')
[System.Environment]::SetEnvironmentVariable('OLLAMA_KV_CACHE_TYPE', 'q8_0', 'User')
```

### 2. Activate Virtual Environment
```powershell
Set-Location "E:\New folder (2)"
.\.venv\Scripts\Activate.ps1
```

### 3. Launch Arjuna
```powershell
python main.py
```

---

## ⌨️ Interactive Slash Commands

| Command | Action |
|---|---|
| `/help` | Display list of available commands |
| `/status` | View real-time GPU VRAM, RAM, and system hardware metrics |
| `/think` | Toggle display of internal reasoning (`<think>` blocks) |
| `/new` | Start a fresh conversation thread |
| `/history` | Print conversation history for the current session |
| `/memories` | Show all stored persistent user facts |
| `/remember <key> = <val>` | Save a persistent memory (e.g. `/remember editor = VS Code`) |
| `/forget <key>` | Delete a persistent memory |
| `/models` | List all models installed in local Ollama |
| `/clear` | Clear terminal screen |
| `/exit` | Exit the assistant |

---

## 🧪 Running Tests

The test suite validates SQLite schema migrations, fact persistence, and local tool execution:

```powershell
.\.venv\Scripts\pytest tests/ -v
```

---

## 🔒 Privacy & Architecture Guarantees
- Zero data leaves the machine.
- No network requests are made during chat completions (100% offline to `http://127.0.0.1:11434`).
- SQLite database resides entirely in your project root (`arjuna.db`).
