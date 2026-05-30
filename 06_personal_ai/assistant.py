"""
Project 6 — Nexus: Personal AI Assistant (fully local & private)
Uses Ollama for the LLM + ChromaDB for persistent memory.

Dependencies:
  pip install chromadb sentence-transformers gradio requests
  Install Ollama: https://ollama.com
  Pull a model:   ollama pull llama3

Usage:
  python assistant.py          # Gradio web UI on http://localhost:7860
  python assistant.py --cli    # Terminal chat mode
"""

import argparse, uuid
from datetime import datetime

import requests
import chromadb
from chromadb.utils import embedding_functions

# ── Config ────────────────────────────────────────────────
OLLAMA_URL  = "http://localhost:11434/api/chat"
MODEL       = "llama3"          # swap to mistral, phi3, gemma, etc.
MEMORY_DIR  = "./memory_db"
COLLECTION  = "nexus_memory"
TOP_K       = 5

SYSTEM_PROMPT = """You are Nexus, a personal cybersecurity AI assistant.
You run fully locally — all data stays private on the user's machine.
You have access to past conversation memory provided as context below.
Be concise, technically precise, and proactive about security insights.
When asked about honeypot logs, scan reports, or audit results, reason
over the provided memory context to give informed, specific answers."""


# ── Memory (ChromaDB vector store) ───────────────────────
_client   = chromadb.PersistentClient(path=MEMORY_DIR)
_embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2")


def _col():
    return _client.get_or_create_collection(
        name=COLLECTION, embedding_function=_embed_fn)


def store_memory(text: str, meta: dict = None) -> None:
    _col().add(
        documents=[text],
        metadatas=[meta or {"ts": datetime.now().isoformat()}],
        ids=[str(uuid.uuid4())]
    )


def retrieve_memories(query: str, k: int = TOP_K) -> list[str]:
    try:
        res = _col().query(query_texts=[query], n_results=k)
        return res["documents"][0] if res["documents"] else []
    except Exception:
        return []


# ── LLM call via Ollama ───────────────────────────────────
def llm(messages: list[dict]) -> str:
    try:
        r = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "messages": messages, "stream": False},
            timeout=120
        )
        r.raise_for_status()
        return r.json()["message"]["content"]
    except requests.ConnectionError:
        return "[!] Ollama is not running. Start it with: ollama serve"
    except Exception as e:
        return f"[!] Error: {e}"


# ── Conversation engine ───────────────────────────────────
class Nexus:
    def __init__(self):
        self.history: list[dict] = []

    def chat(self, user_input: str) -> str:
        # Build memory context
        memories  = retrieve_memories(user_input)
        mem_block = ""
        if memories:
            mem_block = "\n\n[Memory context — from past conversations]\n"
            mem_block += "\n---\n".join(memories[:3])

        # Compose messages
        messages = [{"role": "system", "content": SYSTEM_PROMPT + mem_block}]
        messages += self.history[-10:]          # last 10 turns for context
        messages.append({"role": "user", "content": user_input})

        reply = llm(messages)

        # Update short-term history
        self.history.append({"role": "user",      "content": user_input})
        self.history.append({"role": "assistant",  "content": reply})

        # Persist to long-term memory
        store_memory(
            f"User: {user_input}\nNexus: {reply}",
            {"ts": datetime.now().isoformat(), "type": "conversation"}
        )

        return reply


# ── CLI mode ──────────────────────────────────────────────
def run_cli():
    nexus = Nexus()
    print("Nexus AI — local cybersecurity assistant")
    print("Type 'exit' to quit\n")
    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if not user_input or user_input.lower() in ("exit", "quit"):
            break
        print(f"Nexus: {nexus.chat(user_input)}\n")


# ── Gradio Web UI ─────────────────────────────────────────
def run_ui():
    import gradio as gr
    nexus = Nexus()

    def chat_fn(message, history):
        return nexus.chat(message)

    with gr.Blocks(title="Nexus AI") as demo:
        gr.Markdown("## 🤖 Nexus — Personal Cybersecurity AI\n"
                    "*Running locally · No data leaves your machine*")
        gr.ChatInterface(
            fn=chat_fn,
            examples=[
                "What attacks did my honeypot detect recently?",
                "Summarise my last password audit report",
                "How do I harden my SSH config?",
                "Explain how SQL injection works",
            ]
        )

    demo.launch(server_name="0.0.0.0", server_port=7860)


# ── Entry point ───────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nexus Personal AI Assistant")
    parser.add_argument("--cli", action="store_true", help="Run in terminal mode")
    args = parser.parse_args()

    if args.cli:
        run_cli()
    else:
        run_ui()
