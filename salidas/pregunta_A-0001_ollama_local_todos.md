# ¿que servidores tengo que deshabilitar?

Debes deshabilitar el servidor **api-pagos-02** (10.20.5.12), identificado como el origen de la exfiltración de datos hacia un C2 (EV-017, EV-018, A-0001) y donde se estableció persistencia mediante crontab (EV-012). Asimismo, se debe aislar el **bastion-01**, que sirvió como punto de salto para el movimiento lateral hacia el servidor de producción (EV-007, EV-008). Finalmente, se debe bloquear la conexión de **api-pagos-02** hacia **db-wallet-02** para detener la extracción masiva de registros de clientes (EV-015).
