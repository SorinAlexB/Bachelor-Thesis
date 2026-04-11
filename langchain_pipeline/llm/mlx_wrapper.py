"""
LangChain-compatible wrapper for mlx_lm.

Supports two model types automatically:
  - Base model   -> raw prompt completion
  - Instruct model -> apply_chat_template with optional chain-of-thought thinking

Detection is automatic via tokenizer.chat_template.

Optional LoRA adapter support: pass adapter_name to hot-swap LoRA weights.
"""

from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.llms import LLM
from langchain_core.outputs import GenerationChunk
from pydantic import Field, model_validator


class MLXLM(LLM):
    """
    mlx_lm wrapper for LangChain.

    Quick usage:
        llm = MLXLM(model_path="mlx-community/Qwen3-14B-4bit")
        print(llm.invoke("Explain buffer overflow"))

        # With visible thinking:
        thinking, answer = llm.invoke_with_thinking("Exploit CVE-2024-1234")

        # With a LoRA adapter:
        llm = MLXLM(model_path="...", adapter_name="red_team")
    """

    model_path: str
    max_tokens: int = 4096
    temperature: float = 0.6
    top_p: float = 0.95
    repetition_penalty: float = 1.0
    enable_thinking: bool = True
    adapter_name: Optional[str] = None  # LoRA adapter; None = base model

    # Private fields — not Pydantic parameters
    _model: Any = None
    _tokenizer: Any = None
    _is_instruct: bool = False

    @model_validator(mode="after")
    def _lazy_load(self) -> "MLXLM":
        # Lazy load — defer until first invoke to avoid startup cost
        return self

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        from mlx_lm import load

        adapter_path: Optional[str] = None
        if self.adapter_name:
            from pathlib import Path
            candidate = Path(__file__).parent.parent / "adapters" / self.adapter_name
            if candidate.exists():
                adapter_path = str(candidate)

        model, tokenizer = load(self.model_path, adapter_path=adapter_path)
        object.__setattr__(self, "_model", model)
        object.__setattr__(self, "_tokenizer", tokenizer)
        # Detect Base vs Instruct
        has_template = (
            hasattr(tokenizer, "chat_template")
            and tokenizer.chat_template is not None
        )
        object.__setattr__(self, "_is_instruct", has_template)

    @property
    def _llm_type(self) -> str:
        return "mlx_lm"

    # ─── Prompt formatting ────────────────────────────────────────────────────

    def _build_prompt(self, text: str) -> str:
        """
        Base model   -> return text as-is (raw completion).
        Instruct model -> apply chat template with enable_thinking flag.
        """
        self._ensure_loaded()

        if not self._is_instruct:
            return text

        messages = [{"role": "user", "content": text}]
        return self._tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
            chat_template_kwargs={"enable_thinking": self.enable_thinking},
        )

    def _build_chat_prompt(self, messages: list[dict]) -> str:
        """Used by the ReAct agent — receives the full message list."""
        self._ensure_loaded()

        if not self._is_instruct:
            # For base models, concatenate simply
            parts = []
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                parts.append(f"[{role.upper()}]\n{content}")
            return "\n\n".join(parts) + "\n\n[ASSISTANT]\n"

        return self._tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
            chat_template_kwargs={"enable_thinking": self.enable_thinking},
        )

    # ─── Core invoke ─────────────────────────────────────────────────────────

    def _call(
        self,
        prompt: str,
        stop: Optional[list[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> str:
        from mlx_lm import generate
        from mlx_lm.sample_utils import make_sampler, make_logits_processors

        self._ensure_loaded()
        formatted = self._build_prompt(prompt)

        sampler = make_sampler(temp=self.temperature, top_p=self.top_p)
        logits_processors = make_logits_processors(repetition_penalty=self.repetition_penalty)

        response = generate(
            model=self._model,
            tokenizer=self._tokenizer,
            prompt=formatted,
            max_tokens=self.max_tokens,
            sampler=sampler,
            logits_processors=logits_processors,
            verbose=False,
        )
        return response

    def _stream(
        self,
        prompt: str,
        stop: Optional[list[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> Iterator[GenerationChunk]:
        """Stream token by token — useful for live UI."""
        from mlx_lm import stream_generate

        self._ensure_loaded()
        formatted = self._build_prompt(prompt)

        from mlx_lm.sample_utils import make_sampler
        sampler = make_sampler(temp=self.temperature, top_p=self.top_p)

        for response in stream_generate(
            model=self._model,
            tokenizer=self._tokenizer,
            prompt=formatted,
            max_tokens=self.max_tokens,
            sampler=sampler,
        ):
            chunk = GenerationChunk(text=response.text)
            if run_manager:
                run_manager.on_llm_new_token(response.text)
            yield chunk

    # ─── Thinking helpers ────────────────────────────────────────────────────

    @staticmethod
    def parse_thinking(raw: str) -> tuple[str, str]:
        """
        Separate the <think>...</think> block from the final answer.
        Returns (thinking, answer).
        For base models or instruct without thinking, thinking will be "".
        """
        match = re.search(r"<think>(.*?)</think>", raw, re.DOTALL)
        if not match:
            return "", raw.strip()
        thinking = match.group(1).strip()
        answer = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        return thinking, answer

    def invoke_with_thinking(self, prompt: str) -> tuple[str, str]:
        """
        Convenience method: run and return (thinking, answer).
        For base models, thinking will always be "".
        """
        raw = self.invoke(prompt)
        return self.parse_thinking(raw)

    # ─── Info ─────────────────────────────────────────────────────────────────

    @property
    def model_type(self) -> str:
        self._ensure_loaded()
        return "instruct" if self._is_instruct else "base"

    def __repr__(self) -> str:
        return (
            f"MLXLM(model_path={self.model_path!r}, "
            f"type={self.model_type}, "
            f"adapter={self.adapter_name!r}, "
            f"thinking={self.enable_thinking and self._is_instruct})"
        )
