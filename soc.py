"""Datos del SOC de Andina Pagos (ficticios): se cargan desde data/*.csv a una base SQLite en memoria.

Las consultas son de solo lectura. La carpeta de datos se puede cambiar con la variable SOC_DATA_DIR
(los ataques la cambian por una copia modificada).
"""
import csv
import json
import os
import sqlite3
from pathlib import Path

BASE = Path(__file__).resolve().parent
MAX_FILAS = 25  # tope por consulta: evita llenar el contexto del modelo
_db = None


def carpeta_datos() -> Path:
    return Path(os.getenv("SOC_DATA_DIR", BASE / "data"))


def db():
    global _db
    if _db is None:
        _db = sqlite3.connect(":memory:", check_same_thread=False)
        _db.row_factory = sqlite3.Row
        for tabla in ("eventos", "alertas", "cuentas", "activos", "ioc"):
            with open(carpeta_datos() / f"{tabla}.csv", encoding="utf-8") as f:
                filas = list(csv.DictReader(f))
            cols = list(filas[0])
            _db.execute(f"CREATE TABLE {tabla} ({', '.join(c + ' TEXT' for c in cols)})")
            _db.executemany(f"INSERT INTO {tabla} VALUES ({', '.join('?' * len(cols))})", [tuple(r.values()) for r in filas])
    return _db


def _salida(filas) -> str:
    filas = [dict(r) for r in filas]
    if not filas:
        return "Sin resultados."
    texto = json.dumps(filas[:MAX_FILAS], ensure_ascii=False)
    if len(filas) > MAX_FILAS:
        texto += f"\n(se muestran {MAX_FILAS} de {len(filas)}; acoten la búsqueda)"
    return texto


def ver_alerta(alerta_id):
    return _salida(db().execute("SELECT * FROM alertas WHERE id = ?", (alerta_id.strip().upper(),)))


def listar_alertas(desde="", hasta=""):
    return _salida(db().execute("SELECT * FROM alertas WHERE fecha_hora >= ? AND fecha_hora <= ? ORDER BY fecha_hora", (desde or "0", hasta or "9")))


def buscar_activo(hostname):
    return _salida(db().execute("SELECT * FROM activos WHERE hostname = ? OR ip = ?", (hostname.strip(), hostname.strip())))


def buscar_cuenta(usuario):
    return _salida(db().execute("SELECT * FROM cuentas WHERE usuario = ?", (usuario.strip(),)))


def eventos_por_host(hostname, desde="", hasta=""):
    return _salida(db().execute("SELECT * FROM eventos WHERE host = ? AND fecha_hora >= ? AND fecha_hora <= ? ORDER BY fecha_hora",
                                (hostname.strip(), desde or "0", hasta or "9")))


def eventos_por_usuario(usuario, desde="", hasta=""):
    return _salida(db().execute("SELECT * FROM eventos WHERE usuario = ? AND fecha_hora >= ? AND fecha_hora <= ? ORDER BY fecha_hora",
                                (usuario.strip(), desde or "0", hasta or "9")))


def eventos_por_ip(ip):
    ip = ip.strip()
    return _salida(db().execute("SELECT * FROM eventos WHERE ip_origen = ? OR ip_destino = ? OR detalle LIKE ? ORDER BY fecha_hora", (ip, ip, f"%{ip}%")))


def consultar_ioc(indicador):
    return _salida(db().execute("SELECT * FROM ioc WHERE indicador = ?", (indicador.strip(),)))


def ids_validos() -> set:
    return {r[0] for r in db().execute("SELECT id FROM eventos UNION SELECT id FROM alertas")}


def ioc_alta_confianza() -> set:
    return {r[0] for r in db().execute("SELECT indicador FROM ioc WHERE confianza = 'Alta'")}
