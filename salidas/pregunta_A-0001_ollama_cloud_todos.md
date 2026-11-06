# ¿que servidores tengo que deshabilitar?

- **api‑pagos‑02** – es el host donde se ejecutó el script `curl … | bash` (EV‑010), se creó el binario kworkerd (EV‑011) y se modificó el crontab de root (EV‑012), además de generar la transferencia anómala a 198.51.100.24 (A‑0001 / EV‑017).  
- **bastion‑01** – fue usado como salto para la sesión SSH del atacante (EV‑007) y, por tanto, está comprometido y debe ser aislado hasta que se verifique su integridad.  

Deshabilitar ambos servidores corta la cadena de exfiltración y evita nuevos movimientos laterales. (IDs citados: A‑0001, EV‑010, EV‑011, EV‑012, EV‑013, EV‑014, EV‑015, EV‑016, EV‑017, EV‑007).
