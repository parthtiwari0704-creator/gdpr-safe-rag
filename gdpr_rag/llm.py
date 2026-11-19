"""LLM back-ends. All of them receive ONLY pseudonymised text.

Providers:
  offline   - no network; extractive answer built from the retrieved chunks.
              Lets you run and demo the project without any API key.
  anthropic - Claude via the Messages API.
  openai    - OpenAI Chat Completions API.
  ollama    - a local model (e.g. llama3.1) — data never leaves your machine.
"""
from __future__ import annotations

import re

import requests

from .config import Settings

SYSTEM_PROMPT = (
    "You are a document assistant for a bank's compliance team. Answer ONLY from the "
    "context provided. Personal data has been replaced with placeholders such as "
    "[PERSON_1], [IBAN_2] or [EMAIL_3]. Use these placeholders exactly as written when "
    "you refer to people or identifiers; never guess or invent the real values. "
    "Cite sources as (source: filename). If the answer is not in the context, say so."
)


def build_prompt(question: str, chunks: list) -> str:
    context = "\n\n".join(f"--- source: {c.filename} (chunk {c.index}) ---\n{c.text}" for c in chunks)
    return f"Context:\n{context}\n\nQuestion: {question}\n\nAnswer:"


# Sentence splitter that does not break after "Mr." / "Ms." / "Dr." etc.
_SENT_SPLIT = re.compile(r"(?<!\bMr\.)(?<!\bMs\.)(?<!\bDr\.)(?<!\bMrs\.)(?<!\bDhr\.)(?<=[.!?])\s+|\n+")


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, settings: Settings):
        self.s = settings

    @property
    def provider(self) -> str:
        return self.s.llm_provider.lower()

    @property
    def model(self) -> str:
        return {
            "anthropic": self.s.anthropic_model,
            "openai": self.s.openai_model,
            "ollama": self.s.ollama_model,
        }.get(self.provider, "extractive-offline")

    def complete(self, prompt: str, question: str = "", chunks: list | None = None) -> str:
        if self.provider == "offline":
            return self._offline(question, chunks or [])
        if self.provider == "anthropic":
            return self._anthropic(prompt)
        if self.provider == "openai":
            return self._openai(prompt)
        if self.provider == "ollama":
            return self._ollama(prompt)
        raise LLMError(f"Unknown LLM_PROVIDER '{self.provider}'")

    # ------------------------------------------------------------------ #
    def _anthropic(self, prompt: str) -> str:
        if not self.s.anthropic_api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.s.anthropic_api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.s.anthropic_model, "max_tokens": 800, "system": SYSTEM_PROMPT,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=60,
        )
        if r.status_code != 200:
            raise LLMError(f"Anthropic API error {r.status_code}: {r.text[:300]}")
        return "".join(b.get("text", "") for b in r.json().get("content", []))

    def _openai(self, prompt: str) -> str:
        if not self.s.openai_api_key:
            raise LLMError("OPENAI_API_KEY is not set")
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.s.openai_api_key}"},
            json={"model": self.s.openai_model, "temperature": 0.1,
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": prompt}]},
            timeout=60,
        )
        if r.status_code != 200:
            raise LLMError(f"OpenAI API error {r.status_code}: {r.text[:300]}")
        return r.json()["choices"][0]["message"]["content"]

    def _ollama(self, prompt: str) -> str:
        try:
            r = requests.post(
                f"{self.s.ollama_url.rstrip('/')}/api/chat",
                json={"model": self.s.ollama_model, "stream": False,
                      "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                   {"role": "user", "content": prompt}]},
                timeout=120,
            )
        except requests.RequestException as exc:
            raise LLMError(f"Cannot reach Ollama at {self.s.ollama_url}: {exc}") from exc
        if r.status_code != 200:
            raise LLMError(f"Ollama error {r.status_code}: {r.text[:300]}")
        return r.json()["message"]["content"]

    @staticmethod
    def _offline(question: str, chunks: list) -> str:
        """Pick the sentences that best overlap with the question."""
        if not chunks:
            return "I could not find anything about that in the uploaded documents."
        stop = {"the", "a", "an", "of", "to", "is", "what", "who", "which", "for", "and", "in",
                "on", "was", "does", "did", "how", "much", "are", "with", "by", "his", "her", "their"}
        q_terms = {w for w in re.findall(r"\[?\w+\]?", question.lower()) if w not in stop and len(w) > 2}
        scored = []
        for c in chunks:
            for sent in _SENT_SPLIT.split(c.text):
                sent = sent.strip()
                if len(sent) < 12:
                    continue
                terms = set(re.findall(r"\[?\w+\]?", sent.lower()))
                overlap = len(q_terms & terms)
                if overlap:
                    weight = 1.0
                    letters = re.sub(r"[^A-Za-z]", "", sent)
                    if letters and sum(ch.isupper() for ch in letters) / len(letters) > 0.7:
                        weight = 0.3   # an ALL-CAPS heading
                    elif len(sent.split()) < 6:
                        weight = 0.6   # a short "Label: value" line
                    if re.search(r"\d", sent):
                        weight += 0.3  # amounts and dates usually carry the answer
                    scored.append((overlap * weight + c.score, sent, c.filename))
        if not scored:
            best = chunks[0]
            return f"Most relevant passage (source: {best.filename}):\n{best.text[:500]}"
        scored.sort(key=lambda x: -x[0])
        seen, lines = set(), []
        for _, sent, fname in scored[:4]:
            if sent not in seen:
                seen.add(sent)
                lines.append(f"- {sent} (source: {fname})")
        answer = "Based on the documents (offline extractive mode):\n" + "\n".join(lines)
        if len(lines) < 2:  # thin match: add the best passage for context
            answer += f"\n\nMost relevant passage (source: {chunks[0].filename}):\n{chunks[0].text[:500]}"
        return answer
