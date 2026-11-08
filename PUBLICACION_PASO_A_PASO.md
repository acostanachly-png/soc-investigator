# Publicar SOC Investigator en internet (sin PowerShell para el profesor)

## Qué vamos a compartir

- **Aplicación**: URL pública de Streamlit, en la que el profesor carga su propio Excel y ve los resultados.
- **PDF final**: un único PDF con portada, informe ejecutivo e informe técnico; se comparte mediante Google Drive en modo *Lector*.
- **Video**: enlace separado a una grabación de máximo 5 minutos.

> IMPORTANTE: este archivo describe los pasos que hay que hacer **en las cuentas del autor**. Descargar este paquete NO significa que ya esté publicado.

## Preparación de seguridad

El archivo ZIP para GitHub contiene **solamente código y datos ficticios de demostración**. No contiene el Excel original del curso, informes que revelen eventos, ni claves de API. Si los logs fueran de una empresa real, no deben subirse a una aplicación pública sin su autorización formal.

## Paso 1 — Crear repositorio GitHub

1. Abre https://github.com/new e inicia sesión.
2. En **Repository name** escribe `soc-investigator` (o nombre distinto si ya existe).
3. Selecciona **Public** para facilitar la demostración académica. También puedes usar un repositorio privado, pero tendrás que autorizar acceso a Streamlit y configurar visibilidad de la app.
4. Pulsa **Create repository**.
5. En el repositorio vacío, elige **uploading an existing file** / **Add file → Upload files**.
6. Descomprime **SOC_Investigator_Para_GitHub.zip** en tu computadora. **Arrastra los archivos que están dentro de la carpeta extraída**, no el ZIP como un solo archivo. Mantén `app.py` y `requirements.txt` en la raíz, `.streamlit/config.toml` en su carpeta; sube el directorio `.streamlit` si GitHub te permite arrastrar carpetas o créalo desde GitHub con un archivo de nombre `.streamlit/config.toml`. Puedes omitir `.streamlit` al principio; la app usa un tema predeterminado.
7. Pulsa **Commit changes**.

## Paso 2 — Desplegar Streamlit

1. Abre https://share.streamlit.io e inicia sesión con GitHub.
2. Pulsa **Create app → Yup, I have an app**.
3. Selecciona el repositorio creado en el paso 1.
4. **Branch:** `main`. **Main file path:** `app.py`.
5. Escoge un subdominio si el nombre está disponible; por ejemplo `soc-investigator-[sufijo]`.
6. Haz clic en **Deploy**. Streamlit instalará los paquetes de `requirements.txt` y ejecutará la aplicación.
7. Copia la URL **real** que se muestre después de desplegar (no inventes la URL antes).

Si aparece un error, abre el registro de la app en Streamlit y verifica que se subieron `engine.py`, `case_engine.py`, `reports.py`, `submission.py`, `ai_helper.py`, `requirements.txt`, `ejemplo_logs_sinteticos.xlsx` y `app.py`.

## Paso 3 — Probar desde el navegador

1. Abre la URL de la aplicación.
2. Selecciona **Ver demostración sintética**; luego ejecuta el análisis para comprobar que funciona con registros de prueba.
3. Cambia a **Subir Excel del curso**, sube el `.xlsx` que te dieron, selecciona la hoja `SIEM Export` y verifica el mapeo automático.
4. Pulsa **Ejecutar análisis de seguridad**.
5. Confirma que aparecen **715 registros** y **6 casos correlacionados** con los parámetros predeterminados.
6. En la pestaña de informes descarga el ejecutivo y el técnico por separado. Introduce la URL real de la aplicación y descarga el **PDF FINAL UNIFICADO**.

## Paso 4 — Entregar el PDF y el video

1. Sube **SOC_Investigator_Entrega_Final.pdf** a Google Drive.
2. En **Compartir → Acceso general**, selecciona **Cualquier persona con el enlace → Lector**.
3. Copia ese enlace al campo del formulario que pida el enlace PDF.
4. Sube el video a YouTube como **No listado** o a Drive con acceso por enlace; coloca ese enlace en el campo de video.
5. Prueba ambos enlaces en una ventana de incógnito, sin sesión iniciada, antes de enviarlos.

## IA: opcional y segura

- La clasificación y la correlación se realizan mediante reglas deterministas; **funcionan sin IA y sin pagar por API**.
- En la sección de redacción asistida, quien la use debe introducir su propia clave API y autorizar el envío de un resumen. La clave no se coloca en GitHub ni se guarda en disco.
- Si decides demostrar la IA en el video, prueba tu cuenta y sus créditos antes de grabar. No muestres la clave en pantalla. No es obligatorio para demostrar los resultados de las reglas.
- Este prototipo no ejecuta consultas a un SIEM real. No almacena los archivos subidos intencionalmente en un backend persistente, pero los procesa temporalmente en un servidor de terceros; no usar con datos sensibles sin permiso.

## Si todavía no has publicado la app

Puedes compartir el PDF **preliminar** para revisar su contenido, pero **para la entrega final conviene regenerarlo desde la app y agregar su URL pública**.

Fuentes oficiales:
- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy
- https://docs.streamlit.io/deploy/streamlit-community-cloud/share-your-app
- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/secrets-management
