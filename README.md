# SOC Investigator — Analizador académico de logs SIEM

Aplicación Streamlit en español para investigar posibles incidentes a partir de exportaciones `.xlsx` de SIEM. Importa datos, sugiere el mapeo de columnas, ejecuta reglas auditables, correlaciona señales, presenta un dashboard y genera un informe ejecutivo, un informe técnico y un único PDF de entrega.

> **Alcance:** herramienta educativa de investigación sobre archivos exportados. No es un SIEM en tiempo real, no sustituye análisis forense, y los resultados automáticos son hipótesis que requieren validación humana.

## Probarlo en Streamlit Community Cloud

1. Publica los archivos de este directorio en un repositorio GitHub.
2. Abre https://share.streamlit.io.
3. Selecciona el repositorio, rama `main`, archivo principal `app.py`.
4. Despliega y comparte la URL asignada. No requiere API para analizar eventos y generar los PDF.

Consulta [PUBLICACION_PASO_A_PASO.md](PUBLICACION_PASO_A_PASO.md) para el proceso completo.

## Ejecutarlo en un equipo local

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Para probar sin cargar un archivo del curso, selecciona **Ver demostración sintética**. Para analizar un Excel propio, selecciona **Subir Excel del curso**, elige la hoja y verifica el mapeo de columnas.

## Flujo de análisis

- **Carga de XLSX:** procesa el archivo recibido en memoria; no intenta ejecutar comandos registrados en su interior.
- **Detección:** reglas de autenticación, privilegios, comandos, acceso remoto y patrones sospechosos.
- **Correlación:** hipótesis sobre secuencias de logs con referencias a identificadores y filas.
- **Dashboard:** estadísticas, gráficos, criticidad y evidencias.
- **Informe:** PDF ejecutivo, PDF técnico y PDF unificado para compartir.
- **IA opcional:** quien quiera obtener narrativas asistidas aporta su propia clave API y acepta el envío de resúmenes agregados. No se envían filas completas a ese componente.

## Seguridad y privacidad

No subas ni incluyas en GitHub registros privados, datos reales de clientes, claves API o contraseñas. La aplicación pública ejecuta las cargas temporalmente en infraestructura de terceros; es solo para escenarios autorizados/sintéticos. No hay almacenamiento persistente de archivos implementado por la aplicación. La función opcional de IA usa una clave temporal escrita por la persona que la activa; no existe una clave maestra compartida.

Código base probado mediante `python -m unittest discover -s tests -v` con archivos de prueba sintéticos.
