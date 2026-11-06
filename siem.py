"""Consola mínima del SIEM de Andina Pagos: consultar la base de logs a mano, como lo haría un analista.

La base tiene cinco días de eventos (del lunes 9 al viernes 13 de marzo de 2026) de VPN, MFA, correo, proxy, SSH,
sudo, EDR, base de datos, WAF y directorio. La mayoría es actividad normal.

Uso:
  python siem.py --resumen                          # cuántos eventos hay por fuente y por día
  python siem.py --usuario m.rojas                  # todo lo que hizo una cuenta
  python siem.py --host api-pagos-02                # todo lo que pasó en un equipo
  python siem.py --ip 198.51.100.24                 # origen, destino o mención de una IP
  python siem.py --texto andinapagos-it.com         # búsqueda libre en el detalle
  python siem.py --fuente MFA --desde 2026-03-13T22:00
  python siem.py --evento EV-017                    # un evento completo
  python siem.py --cuenta m.rojas | --activo api-pagos-02 | --ioc 198.51.100.24
"""
import argparse
import sys

import pandas as pd

import soc


def mostrar(filas, completo=False):
    if not filas:
        print("Sin resultados.")
        return
    df = pd.DataFrame(filas)
    if "detalle" in df.columns and not completo:
        df["detalle"] = df["detalle"].str.slice(0, 90)
    with pd.option_context("display.max_rows", 500, "display.width", 250, "display.max_colwidth", 400 if completo else 90):
        print(df.to_string(index=False))
    print(f"\n{len(df)} fila(s)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--usuario")
    ap.add_argument("--host")
    ap.add_argument("--ip")
    ap.add_argument("--texto")
    ap.add_argument("--fuente")
    ap.add_argument("--desde", default="")
    ap.add_argument("--hasta", default="")
    ap.add_argument("--evento")
    ap.add_argument("--cuenta")
    ap.add_argument("--activo")
    ap.add_argument("--ioc")
    ap.add_argument("--resumen", action="store_true")
    a = ap.parse_args()
    db = soc.db()
    q = lambda sql, *p: [dict(r) for r in db.execute(sql, p)]  # noqa: E731
    if a.resumen:
        print(pd.DataFrame(q("SELECT substr(fecha_hora, 1, 10) AS dia, fuente, count(*) AS eventos FROM eventos GROUP BY 1, 2"))
              .pivot(index="fuente", columns="dia", values="eventos").fillna(0).astype(int).to_string())
        print(f"\nTotal: {q('SELECT count(*) AS n FROM eventos')[0]['n']} eventos · {q('SELECT count(*) AS n FROM alertas')[0]['n']} alertas")
        return
    if a.evento:
        return mostrar(q("SELECT * FROM eventos WHERE id = ?", a.evento.upper()), completo=True)
    if a.cuenta:
        return mostrar(q("SELECT * FROM cuentas WHERE usuario = ?", a.cuenta), completo=True)
    if a.activo:
        return mostrar(q("SELECT * FROM activos WHERE hostname = ? OR ip = ?", a.activo, a.activo), completo=True)
    if a.ioc:
        return mostrar(q("SELECT * FROM ioc WHERE indicador = ?", a.ioc), completo=True)
    cond, par = ["fecha_hora >= ?", "fecha_hora <= ?"], [a.desde or "0", a.hasta or "9"]
    if a.usuario:
        cond.append("usuario = ?"); par.append(a.usuario)  # noqa: E702
    if a.host:
        cond.append("host = ?"); par.append(a.host)  # noqa: E702
    if a.fuente:
        cond.append("fuente = ?"); par.append(a.fuente.upper())  # noqa: E702
    if a.ip:
        cond.append("(ip_origen = ? OR ip_destino = ? OR detalle LIKE ?)"); par += [a.ip, a.ip, f"%{a.ip}%"]  # noqa: E702
    if a.texto:
        cond.append("detalle LIKE ?"); par.append(f"%{a.texto}%")  # noqa: E702
    if len(cond) == 2 and not (a.desde or a.hasta):
        print(__doc__)
        return
    mostrar(q(f"SELECT id, fecha_hora, fuente, host, usuario, ip_origen, ip_destino, accion, detalle FROM eventos WHERE {' AND '.join(cond)} ORDER BY fecha_hora", *par))


if __name__ == "__main__":
    sys.exit(main())
