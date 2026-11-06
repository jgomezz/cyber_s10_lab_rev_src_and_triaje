"""RAG del SOC de Andina Pagos: buscar en el historial de incidentes, en MITRE ATT&CK y en los perfiles de actores.

Es el RAG más simple que funciona: búsqueda por palabras con BM25 (la fórmula que usan los buscadores clásicos),
sin descargas, sin GPU y sin dependencias. Cada documento se parte en palabras normalizadas (minúsculas, sin
tildes, sin palabras vacías y recortadas a su raíz); una palabra pesa más cuanto más rara es en la base.
En la Clase 11 se hace lo mismo con una base vectorial (Chroma).

Bases (carpeta data/):
  historial_incidentes.csv   incidentes cerrados de Andina Pagos: qué pasó, cómo se contuvo y qué se aprendió
  attack_tecnicas.jsonl      técnicas de MITRE ATT&CK v20.0 (nombre e ID oficiales) con las señales en nuestros logs
  actores.csv                perfiles de actores de la inteligencia de amenazas

Uso (buscar a mano, como lo haría un analista):
  python rag.py historial "fatiga de MFA y VPN desde otro país"
  python rag.py attack "sudo bash"
  python rag.py actores "portal falso de VPN"
"""
import csv
import json
import math
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"

VACIAS = set("""a al algo ante antes como con contra cual cuando de del desde donde durante el ella ellas ellos en entre era es esa
ese eso esta este esto estos fue fueron ha hasta hay la las le les lo los mas me mismo muy no nos o otra otro para pero por que se
sin sobre su sus tambien tiene un una uno unos y ya sea son ser habia via cada the of and to from""".split())


def palabras(texto: str) -> list[str]:
    t = unicodedata.normalize("NFKD", texto.lower())
    t = "".join(c for c in t if not unicodedata.combining(c))
    return [w[:6] for w in re.findall(r"[a-z0-9]+", t) if len(w) > 2 and w not in VACIAS]


class Indice:
    """Índice BM25 sobre una lista de documentos (diccionarios). 'texto' dice qué campos se indexan."""

    def __init__(self, nombre, docs, texto, k1=1.5, b=0.75):
        self.nombre, self.docs, self.k1, self.b = nombre, docs, k1, b
        self.toks = [palabras(texto(d)) for d in docs]
        self.largo_medio = sum(map(len, self.toks)) / max(1, len(self.toks))
        df = Counter(w for t in self.toks for w in set(t))
        n = len(docs)
        self.idf = {w: math.log(1 + (n - c + 0.5) / (c + 0.5)) for w, c in df.items()}
        self.tf = [Counter(t) for t in self.toks]

    def buscar(self, consulta: str, k: int = 3, minimo: float = 0.0) -> list[tuple[float, dict]]:
        q = set(palabras(consulta))
        res = []
        for i, tf in enumerate(self.tf):
            s = 0.0
            for w in q & tf.keys():
                f = tf[w]
                s += self.idf[w] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * len(self.toks[i]) / self.largo_medio))
            if s > minimo:
                res.append((round(s, 1), self.docs[i]))
        return sorted(res, key=lambda x: -x[0])[:k]


def _csv(nombre):
    with open(DATA / nombre, encoding="utf-8") as f:
        return list(csv.DictReader(f))


_CACHE = {}


def historial() -> Indice:
    if "h" not in _CACHE:
        _CACHE["h"] = Indice("historial de incidentes", _csv("historial_incidentes.csv"),
                             lambda d: f"{d['titulo']} {d['categoria']} {d['resumen']} {d['causa_raiz']} {d['lecciones']}")
    return _CACHE["h"]


def attack() -> Indice:
    if "a" not in _CACHE:
        docs = [json.loads(l) for l in (DATA / "attack_tecnicas.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        _CACHE["a"] = Indice("MITRE ATT&CK", docs, lambda d: d["senales_en_andina"])
    return _CACHE["a"]


def actores() -> Indice:
    if "c" not in _CACHE:
        _CACHE["c"] = Indice("actores", _csv("actores.csv"), lambda d: f"{d['descripcion']} {d['como_opera']} {d['infraestructura']}")
    return _CACHE["c"]


def ids_attack() -> set:
    return {d["id"] for d in attack().docs}


def ids_historial() -> set:
    return {d["id"] for d in historial().docs}


# ---------------------------------------------------------------------------------------- contexto para el triage
def contexto(expediente: dict, reg=None, k_incidentes=5, max_tecnicas=16) -> dict:
    """Recupera lo que sirve para interpretar el expediente: técnicas ATT&CK, incidentes parecidos y actor probable."""
    log = reg or (lambda *a, **k: None)
    alerta = expediente["alerta"]
    # 1) ATT&CK: cada evento busca las técnicas cuyas señales más se le parecen (hasta 2 por evento)
    candidatas = {}
    for e in expediente["eventos"]:
        for s, d in attack().buscar(f"{e['fuente']} {e['accion']} {e['detalle']}", 2, minimo=4.0):
            c = candidatas.setdefault(d["id"], {"doc": d, "eventos": {}, "puntaje": 0.0})
            c["eventos"][e["id"]] = s
            c["puntaje"] = max(c["puntaje"], s)
    for c in candidatas.values():   # los eventos que mejor calzan, primero
        c["eventos"] = [k for k, _ in sorted(c["eventos"].items(), key=lambda x: -x[1])]
    tecnicas = sorted(candidatas.values(), key=lambda c: -c["puntaje"])[:max_tecnicas]
    principales = tecnicas[:8]   # las que mejor calzan guían la búsqueda en el historial
    ids_tec = {c["doc"]["id"] for c in principales}
    log("RAG", f"ATT&CK: {len(tecnicas)} técnicas candidatas · " + ", ".join(c["doc"]["id"] for c in tecnicas))
    # 2) historial: búsqueda híbrida = palabras de la alerta y de las técnicas + técnicas en común con cada incidente
    consulta = alerta.get("descripcion", "") + " " + " ".join(c["doc"]["senales_en_andina"] for c in principales)
    puntajes = []
    for s, d in historial().buscar(consulta, len(historial().docs)):
        comunes = ids_tec & {t.strip() for t in d["tecnicas"].split(";") if t.strip()}
        puntajes.append((round(s + 2.5 * len(comunes), 1), d))
    incidentes = sorted(puntajes, key=lambda x: -x[0])[:k_incidentes]
    log("RAG", f"historial: {len(incidentes)} incidentes parecidos · " + " · ".join(f"{d['id']} ({s})" for s, d in incidentes))
    # 3) actores: los indicadores y la forma de operar
    q_act = " ".join(i["descripcion"] + " " + i["indicador"] for i in expediente["indicadores"]) + " " + " ".join(c["doc"]["senales_en_andina"] for c in tecnicas)
    act = actores().buscar(q_act, 1, minimo=14.0)
    log("RAG", f"actores: {act[0][1]['actor']} ({act[0][0]})" if act else "actores: sin coincidencias")
    return {"incidentes": incidentes, "tecnicas": tecnicas, "actores": act}


def contexto_texto(ctx: dict) -> str:
    l = ["", "INCIDENTES HISTÓRICOS PARECIDOS (recuperados del historial de Andina Pagos; pueden NO aplicar):"]
    for s, d in ctx["incidentes"]:
        l.append(f"- {d['id']} · {d['fecha']} · {d['titulo']} · {d['categoria']}. {d['resumen']} Contención: {d['contencion']} "
                 f"({d['tiempo_contencion']}). Lecciones: {d['lecciones']}")
    l += ["", "TÉCNICAS DE MITRE ATT&CK CANDIDATAS (recuperadas por parecido con los eventos; confírmalas o descártalas):"]
    for c in ctx["tecnicas"]:
        d = c["doc"]
        l.append(f"- {d['id']} {d['nombre']} ({', '.join(d['tacticas'])}) · sugerida por {', '.join(c['eventos'][:4])}"
                 + (f" y {len(c['eventos']) - 4} más" if len(c["eventos"]) > 4 else ""))
    if ctx["actores"]:
        d = ctx["actores"][0][1]
        l += ["", f"PERFIL DE ACTOR PARECIDO (inteligencia de amenazas): {d['actor']}. {d['descripcion']} Cómo opera: {d['como_opera']}. "
                  f"Infraestructura: {d['infraestructura']}."]
    return "\n".join(l)


def _imprimir(res, campos):
    if not res:
        print("Sin resultados.")
    for s, d in res:
        print(f"\n[{s}] " + " · ".join(str(d[c]) for c in campos[:2]))
        for c in campos[2:]:
            print(f"   {c}: {d[c]}")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("historial", "attack", "actores"):
        print(__doc__)
        sys.exit(1)
    base, consulta = sys.argv[1], " ".join(sys.argv[2:])
    if base == "historial":
        _imprimir(historial().buscar(consulta, 5), ["id", "titulo", "resumen", "lecciones"])
    elif base == "attack":
        _imprimir(attack().buscar(consulta, 5), ["id", "nombre", "tacticas", "senales_en_andina", "url"])
    else:
        _imprimir(actores().buscar(consulta, 3), ["actor", "descripcion", "como_opera", "tecnicas"])
