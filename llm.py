"""Cliente único para todos los proveedores del curso (kit común).

    from llm import chat
    print(chat("Resume la política en 3 puntos", provider="groq"))

El proveedor y el modelo se definen en config.yaml; las claves, en .env.
"""
import json
import os
import re
from pathlib import Path

import yaml
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
os.environ.setdefault("LITELLM_LOG", "ERROR")

import litellm  # noqa: E402  (se importa después de cargar .env)

litellm.suppress_debug_info = True

with open(BASE / "config.yaml", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)


def provider_settings(provider: str | None = None) -> dict:
    """Devuelve modelo, URL y clave del proveedor pedido (o del proveedor por defecto)."""
    name = provider or CONFIG["default"]
    if name not in CONFIG["providers"]:
        raise ValueError(f"Proveedor '{name}' no existe en config.yaml. Opciones: {', '.join(CONFIG['providers'])}")
    p = CONFIG["providers"][name]
    settings = {"model": p["model"]}
    if p.get("api_base"):
        settings["api_base"] = p["api_base"]
    if p.get("api_key_env"):
        key = os.getenv(p["api_key_env"], "").strip()
        if not key:
            raise RuntimeError(f"Falta {p['api_key_env']} en el archivo .env (proveedor '{name}').")
        settings["api_key"] = key
    return settings


def _completar(**kwargs):
    """litellm.completion con espera automática ante límites por minuto (error 429).

    Si el proveedor indica cuánto esperar ("try again in 12s"), espera eso; si no, 20 s. Reintenta hasta 4 veces.
    Un límite diario no se resuelve esperando: en ese caso el error se muestra y conviene cambiar de proveedor.
    """
    import time
    for intento in range(5):
        try:
            return litellm.completion(**kwargs)
        except litellm.RateLimitError as e:
            texto = str(e)
            if intento == 4 or re.search(r"per day|daily|TPD|RPD", texto, flags=re.I):
                raise
            m = re.search(r"(?:try again|retry) in (?:(\d+)m)?(\d+(?:\.\d+)?)s", texto, flags=re.I)
            espera = min(60.0, (int(m.group(1) or 0) * 60 + float(m.group(2))) + 1) if m else 20.0
            print(f"    (límite por minuto del proveedor: espero {espera:.0f} s y reintento)")
            time.sleep(espera)


def chat(prompt: str, provider: str | None = None, system: str | None = None,
         json_mode: bool = False, temperature: float = 0.2, timeout: int = 180) -> str:
    """Envía un mensaje y devuelve el texto de la respuesta."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    kwargs = provider_settings(provider)
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    try:
        resp = _completar(messages=messages, temperature=temperature, timeout=timeout, **kwargs)
    except litellm.BadRequestError as e:
        # Algunos proveedores no aceptan response_format: se reintenta sin él (el prompt ya pide JSON)
        if not json_mode or "response_format" not in str(e).lower() and "json" not in str(e).lower():
            raise
        kwargs.pop("response_format", None)
        resp = _completar(messages=messages, temperature=temperature, timeout=timeout, **kwargs)
    return resp.choices[0].message.content or ""


def extraer_json(texto: str):
    """Convierte la respuesta en un objeto JSON aunque venga con ```json ... ``` o texto alrededor."""
    texto = texto.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", texto, flags=re.S)
    if m:
        texto = m.group(1).strip()
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        inicio = min([i for i in (texto.find("{"), texto.find("[")) if i >= 0], default=-1)
        if inicio < 0:
            raise
        fin = max(texto.rfind("}"), texto.rfind("]"))
        return json.loads(texto[inicio:fin + 1])


def chat_json(prompt: str, esquema, provider: str | None = None, system: str | None = None, intentos: int = 2):
    """Pide un JSON y lo valida con un modelo de Pydantic. Si no es válido, reintenta explicando el error.

    Devuelve (objeto_validado, intentos_usados). Si todos fallan, lanza ValueError con el último error.
    """
    from pydantic import ValidationError
    error = ""
    for intento in range(1, intentos + 1):
        texto = chat(prompt, provider=provider, system=system, json_mode=True)
        try:
            return esquema.model_validate(extraer_json(texto)), intento
        except (json.JSONDecodeError, ValidationError, ValueError) as e:
            error = str(e).splitlines()[0]
            prompt += f"\n\nTu respuesta anterior no era válida ({error}). Responde solo el JSON con los campos y valores pedidos."
    raise ValueError(f"El modelo no entregó un JSON válido: {error}")


def chat_herramientas(messages: list, tools: list, provider: str | None = None, temperature: float = 0.0, timeout: int = 180):
    """Una vuelta de tool calling: devuelve el mensaje del modelo (puede traer tool_calls)."""
    resp = _completar(messages=messages, tools=tools, tool_choice="auto", temperature=temperature,
                              timeout=timeout, **provider_settings(provider))
    return resp.choices[0].message


def smol_model(provider: str | None = None):
    """Modelo para agentes de smolagents (clases 15 a 17) con la misma configuración."""
    from smolagents import LiteLLMModel
    s = provider_settings(provider)
    return LiteLLMModel(model_id=s["model"], api_base=s.get("api_base"), api_key=s.get("api_key"), temperature=0.0)


class EmbeddingLocal:
    """Embeddings léxicos locales (hashing de palabras y pares de palabras): sin descargas, sin API y sin GPU.

    No entienden sinónimos como un modelo semántico, pero para buscar artículos por sus términos funcionan bien.
    """
    DIM = 1024
    VACIAS = set("a al ante con de del desde el en entre es la las lo los o para por que se según sin su sus un una y".split())

    @classmethod
    def vector(cls, texto: str) -> list[float]:
        import hashlib
        import math
        import unicodedata
        t = unicodedata.normalize("NFKD", texto.lower())
        t = "".join(c for c in t if not unicodedata.combining(c))
        palabras = [w[:7] for w in re.findall(r"[a-z0-9]+", t) if w not in cls.VACIAS and len(w) > 1]
        v = [0.0] * cls.DIM
        for termino in palabras + [a + "_" + b for a, b in zip(palabras, palabras[1:])]:
            h = int(hashlib.md5(termino.encode()).hexdigest(), 16)
            v[h % cls.DIM] += 1.0 if h & 1 else -1.0
        v = [math.copysign(math.log1p(abs(x)), x) for x in v]
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / n for x in v]


def _embedding_local():
    from llama_index.core.embeddings import BaseEmbedding

    class _Local(BaseEmbedding):
        def _get_text_embedding(self, text: str):
            return EmbeddingLocal.vector(text)

        def _get_query_embedding(self, query: str):
            return EmbeddingLocal.vector(query)

        async def _aget_query_embedding(self, query: str):
            return EmbeddingLocal.vector(query)

    return _Local(model_name="local-hash-1024")


def embed_model():
    """Modelo de embeddings de LlamaIndex según config.yaml (sección embeddings)."""
    cfg = CONFIG["embeddings"]
    if cfg["provider"] == "local":
        return _embedding_local()
    if cfg["provider"] == "ollama":
        from llama_index.embeddings.ollama import OllamaEmbedding
        return OllamaEmbedding(model_name=cfg["ollama_model"], base_url=cfg["ollama_base"])
    raise ValueError("embeddings.provider debe ser 'local' u 'ollama' en config.yaml")
