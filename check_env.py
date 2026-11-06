"""Prueba cada proveedor del curso y muestra cuáles responden.

Uso:  python check_env.py            (prueba todos)
      python check_env.py groq       (prueba solo uno)
"""
import sys
import time

from llm import CONFIG, chat

PROMPT = "Responde solo con la palabra: listo"


def probar(nombre: str) -> bool:
    inicio = time.time()
    try:
        respuesta = chat(PROMPT, provider=nombre, timeout=60).strip()
        print(f"  OK     {nombre:<13} {time.time() - inicio:5.1f} s  -> {respuesta[:40]}")
        return True
    except Exception as e:  # mostramos el motivo en una línea, sin el traceback completo
        motivo = str(e).splitlines()[0][:110] if str(e) else type(e).__name__
        etiqueta = "OPCIONAL" if nombre == "ollama_local" else "FALLA "
        print(f"  {etiqueta} {nombre:<13} {motivo}")
        return False


if __name__ == "__main__":
    nombres = sys.argv[1:] or list(CONFIG["providers"])
    print("Probando proveedores (puede tardar hasta un minuto por proveedor)...\n")
    ok = [n for n in nombres if probar(n)]
    print(f"\n{len(ok)} de {len(nombres)} proveedores responden.")
    if "ollama_local" in nombres and "ollama_local" not in ok:
        print("ollama_local es opcional: solo para equipos con 16 GB de RAM o GPU.")
    if "groq_oss" in nombres and "groq_oss" not in ok:
        print("ATENCIÓN: groq_oss es el proveedor principal de esta clase. Revisa GROQ_API_KEY en .env (cada uno con su propia clave).")
    if len([n for n in ok if n != "ollama_local"]) < 2:
        print("Necesitas al menos dos proveedores en la nube funcionando (groq_oss y otro): revisa la guía de preparación.")
    sys.exit(0 if ok else 1)
