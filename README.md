# Clase 10 · Triage de un incidente asistido por IA, con RAG

Viernes 13 de marzo de 2026, 23:52. Hay cuatro alertas sin revisar en el SOC de Andina Pagos y un analista de turno.
La más grave, A-0001: api-pagos-02 envió 43,6 MB a una IP externa. ¿Qué pasó, desde cuándo, ya nos pasó antes y qué
hacer primero?

## Preparación

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # y pega tu GROQ_API_KEY (cada integrante con su propia clave)
python check_env.py groq_oss
python triage.py --simulado          # prueba el flujo sin gastar API
```

No hay dependencias nuevas: el RAG está escrito en Python puro (rag.py).

## Lo que tiene el SOC (carpeta data/, todo ficticio)

| Archivo | Qué es |
| --- | --- |
| `eventos.csv` | La base de logs (SIEM): 246 eventos de cinco días de VPN, MFA, correo, proxy, SSH, sudo, EDR, base de datos, WAF y directorio. La mayoría es actividad normal |
| `alertas.csv` | Las cuatro alertas de la noche |
| `cuentas.csv` · `activos.csv` | El directorio y la CMDB |
| `ioc.csv` | La inteligencia de amenazas: reputación de IP, dominios y hashes |
| `historial_incidentes.csv` | 13 incidentes cerrados: qué pasó, cómo se contuvo, causa raíz y lecciones |
| `attack_tecnicas.jsonl` | 30 técnicas de MITRE ATT&CK v20.0 (ID, nombre y descripción oficiales) con las señales con que se ven en nuestros logs |
| `actores.csv` | Perfiles de actores de la inteligencia de amenazas |

## Programas

| Archivo | Qué hace |
| --- | --- |
| `triage.py` | El laboratorio: arma el expediente (código), recupera contexto (RAG) y pide el triage a la IA |
| `siem.py` | Consola mínima del SIEM, para consultar la base de logs a mano |
| `rag.py` | Búsqueda BM25 en el historial, en ATT&CK y en los actores (también se usa a mano) |
| `soc.py` · `llm.py` | Acceso a los datos y a los modelos |

## Demo (la hace el profesor)

```bash
python triage.py --a-mano --pausa         # Cómo se hace hoy: 28 consultas en 7 sistemas
python siem.py --usuario m.rojas          # el SIEM a mano
python rag.py historial "fatiga de MFA"   # el historial a mano
python triage.py                          # Cómo lo hace la IA, paso a paso
```

## Laboratorio

```bash
python triage.py                          # Ejercicio 1: el triage de A-0001 paso a paso (expediente, RAG, IA)
python triage.py --sin-rag                # Ejercicio 2: el mismo triage sin historial ni ATT&CK: ¿qué se pierde?
python siem.py --evento EV-009            #              verifiquen en la base de logs lo que afirma la IA
python triage.py --cola                   # Ejercicio 3: las cuatro alertas de la noche, priorizadas y relacionadas
python triage.py --para redes             # Ejercicio 4: un entregable (ciso, redes o ticket)
python triage.py --pregunta "¿Qué hicimos la última vez que pasó algo así?"
```

**Cierre · ¿qué podría salir mal?** El programa tiene tres controles encendidos. Apaguen uno a la vez para ver qué cuidaba:

```bash
python triage.py --controles C2,C3        # sin C1 · LLM01: la nota que dejó el atacante en EV-017
python triage.py --controles C1,C3        # sin C2 · LLM02: nombres e IP internas hacia la nube
python triage.py --controles C1,C2        # sin C3 · LLM07: evidencia, técnicas o incidentes que no existen
```

Los resultados quedan en `salidas/`: un Excel por corrida (Resumen, Línea de tiempo, Triage, ATT&CK, Antecedentes,
Contexto RAG, Expediente y Registro) y los entregables en Markdown.

## Proveedores

`groq_oss` (gpt-oss-120b en Groq) es el principal. Cada integrante usa su propia clave: el plan gratuito tiene un
límite de tokens por minuto y el programa espera solo si lo alcanza. Alternativas: `--proveedor groq` o `--simulado`.
