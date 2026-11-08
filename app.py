"""SOC Investigator: análisis offline de exportaciones .xlsx de un SIEM."""
from __future__ import annotations

from collections import Counter
from io import BytesIO
import hashlib
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from engine import FIELDS, analyze, normalize_logs, suggest_mapping, summarize
from case_engine import detect_cases
from reports import build_pdf
from submission import build_submission_pdf

st.set_page_config(page_title="SOC Investigator | Análisis de logs", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
.stApp { background: #0b1020; color: #e5ebf5; }
[data-testid="stSidebar"] { background: #141126; }
[data-testid="stMetric"] { background: #1e1b36; padding: 15px 18px; border: 1px solid #373052; border-radius: 13px; }
h1, h2, h3 { color: #f8fafc !important; }
[data-testid="stFileUploader"] { border: 1px dashed #8b5cf6; border-radius: 12px; padding: 12px; }
.hero {border:1px solid #473579; background: linear-gradient(110deg,#171330,#2c2056); border-radius:18px;padding:24px 30px;margin-bottom:20px;}
.hero h1{font-size:2.25rem;margin:0 0 10px 0;}
.hero p{color:#d0ddf2; margin:0;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🛡️ SOC Investigator</h1><p>Investigación de posibles incidentes de seguridad · Importación Excel · Correlación de eventos · Informes auditables</p></div>', unsafe_allow_html=True)

with st.sidebar:
    st.subheader("⚙️ Configuración de detección")
    threshold = st.slider("Intentos fallidos para alertar", 3, 12, 5)
    minutes = st.slider("Ventana de fuerza bruta (min)", 5, 60, 10, 5)
    night_start, night_end = st.slider("Horario a revisar (según reloj Excel)", 0, 23, (0, 5))
    st.divider()
    st.caption("Modo de funcionamiento: análisis local sobre el Excel. No se conecta a Microsoft Sentinel ni a un SIEM en vivo.")
    st.caption("La IA es opcional y solo participa en la redacción; el motor de evidencias funciona sin clave API.")

st.subheader("1. Cargar registros exportados")
source_mode = st.radio("Fuente de datos", ["Subir Excel del curso", "Ver demostración sintética"], horizontal=True)
if source_mode == "Ver demostración sintética":
    file_name = "ejemplo_logs_sinteticos.xlsx"
    raw_bytes = (Path(__file__).parent / file_name).read_bytes()
    st.info("Modo demostración: registros inventados para probar la aplicación. Para ver los seis casos del curso, carga el Excel real.")
else:
    file = st.file_uploader("Selecciona el Excel facilitado por el curso (.xlsx)", type=["xlsx"])
    if file is None:
        st.info("Sube el Excel entregado por el curso o elige la demostración sintética. No cargues registros empresariales reales en una aplicación pública sin autorización.")
        st.markdown("**Flujo de trabajo:** ① Importar Excel → ② Mapear columnas → ③ Ejecutar reglas → ④ Inspeccionar evidencias → ⑤ Descargar los informes PDF.")
        st.stop()
    file_name = file.name
    raw_bytes = file.getvalue()
if len(raw_bytes) > 20 * 1024 * 1024:
    st.error("Este prototipo limita el análisis a archivos de 20 MB para evitar bloquear el navegador.")
    st.stop()
try:
    excel = pd.ExcelFile(BytesIO(raw_bytes), engine="openpyxl")
    sheet_name = st.selectbox("Hoja a analizar", excel.sheet_names)
    df = pd.read_excel(BytesIO(raw_bytes), sheet_name=sheet_name, engine="openpyxl", dtype=object)
    df.columns = [str(c) for c in df.columns]
except Exception as exc:
    st.error(f"No se pudo abrir el archivo como Excel .xlsx válido: {exc}")
    st.stop()

if df.empty:
    st.warning("La hoja elegida está vacía.")
    st.stop()
if len(df) > 50000:
    st.error("El prototipo está limitado a 50 000 filas por ejecución. Podemos ampliarlo cuando conozcamos el tamaño del archivo del curso.")
    st.stop()

st.success(f"Archivo recibido: {file_name} | Hoja '{sheet_name}' | {len(df):,} registros | {len(df.columns)} columnas")
with st.expander("👁️ Vista previa del archivo original", expanded=False):
    st.dataframe(df.head(30), use_container_width=True, hide_index=True)

st.subheader("2. Asociar columnas del Excel con campos SOC")
st.caption("El sistema sugiere campos automáticamente. Revisa especialmente fecha/hora, usuario, IP, evento, estado e ID de evento. Las columnas que no existan pueden quedar como 'No disponible'.")
auto = suggest_mapping(list(df.columns))
options = ["No disponible"] + list(df.columns)
with st.form("mapping_form"):
    cols = st.columns(2)
    mapping = {}
    for i, (key, title) in enumerate(FIELDS.items()):
        with cols[i % 2]:
            proposal = auto.get(key)
            value = st.selectbox(title, options, index=options.index(proposal) if proposal in options else 0, key=f"map_{sheet_name}_{key}")
            mapping[key] = None if value == "No disponible" else value
    st.markdown("#### Parámetros actuales")
    st.caption(f"Fuerza bruta: ≥{threshold} fallos en {minutes} min. Horario de revisión: {night_start:02d}:00-{night_end:02d}:59.")
    clicked = st.form_submit_button("🔍 Ejecutar análisis de seguridad", type="primary", use_container_width=True)

signature_data = {"file": hashlib.sha256(raw_bytes).hexdigest(), "sheet": sheet_name, "map": mapping,
                  "threshold": threshold, "minutes": minutes, "night": [night_start, night_end]}
signature = hashlib.sha256(json.dumps(signature_data, sort_keys=True).encode()).hexdigest()

if clicked:
    if not (mapping["event"] or mapping["status"] or mapping["event_id"] or mapping["command"]):
        st.error("Asocia al menos una columna de evento, estado, ID de evento o comando para realizar un análisis útil.")
    else:
        try:
            logs = normalize_logs(df.reset_index(drop=True), mapping)
            findings, limitations = analyze(logs, brute_threshold=threshold, window_minutes=minutes,
                                             late_hour_start=night_start, late_hour_end=night_end)
            cases = detect_cases(logs)
            st.session_state["analysis"] = {"signature": signature, "logs": logs, "findings": findings,
                                             "limitations": limitations, "summary": summarize(logs, findings), "cases": cases}
            st.session_state["ai_exec"] = ""
            st.session_state["ai_tech"] = ""
            st.session_state["ai_cases"] = {}
        except Exception as exc:
            st.error(f"Error durante el análisis: {exc}")

result = st.session_state.get("analysis")
if not result or result["signature"] != signature:
    st.info("Pulsa «Ejecutar análisis de seguridad» para generar resultados. Si modificaste la configuración, ejecútalo de nuevo.")
    st.stop()

logs = result["logs"]
findings = result["findings"]
limitations = result["limitations"]
summary = result["summary"]
cases = result.get("cases", [])

st.divider()
st.subheader("3. Resultados de investigación")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Registros", f"{summary['registros']:,}")
c2.metric("Casos correlacionados", len(cases))
c3.metric("Altos / críticos", summary["altos"])
c4.metric("Usuarios distintos", summary["usuarios"])
c5.metric("IP de origen", summary["ip_origen"])

if findings:
    st.warning("Se detectaron señales que requieren investigación. No equivalen por sí solas a incidentes confirmados.")
else:
    st.info("No hubo coincidencias con las reglas implementadas. Esto no descarta incidentes no cubiertos por los logs o las reglas.")

tab_cases, tab_finds, tab_dash, tab_reports, tab_method = st.tabs(["🚨 Casos de investigación", "🧩 Alertas y evidencias", "📊 Dashboard", "📄 Dos informes PDF + IA", "📚 Metodología"])

with tab_cases:
    st.markdown("### Hipótesis de incidentes correlacionados")
    st.caption("Un caso reúne varias señales y filas de evidencia. No representa un incidente confirmado ni demuestra causalidad.")
    if not cases:
        st.info("No se identificaron cadenas multiseñal con las reglas implementadas. Revisa las alertas individuales.")
    for case in cases:
        with st.expander(f"{case['id']} · {case['criticidad']} · {case['titulo']}", expanded=False):
            st.write("**Justificación:**", case["justificacion"])
            st.write("**Certeza:**", case["confianza"])
            st.write("**Acción recomendada:**", case["recomendacion"])
            suggestion = st.session_state.get("ai_cases", {}).get(case["id"])
            if suggestion:
                st.info("🤖 **Interpretación asistida por IA (borrador):** " + suggestion["interpretacion"])
                st.write("**Qué falta confirmar:**", suggestion["que_falta_confirmar"])
                st.caption("Referencias citadas por la IA (validadas contra este caso): " + (", ".join(suggestion["referencias"]) or "Ninguna"))
            st.caption("Filas del Excel: " + ", ".join(map(str, case["filas"])))
            st.dataframe(pd.DataFrame(case["evidencias"]), use_container_width=True, hide_index=True)
    st.download_button("Descargar casos de investigación (JSON)", data=json.dumps(cases, ensure_ascii=False, indent=2), file_name="casos_correlacionados.json", mime="application/json")

with tab_finds:
    if findings:
        selected_severities = st.multiselect("Filtrar por criticidad", ["Crítico", "Alto", "Medio", "Bajo"], default=["Crítico", "Alto", "Medio", "Bajo"])
        for f in findings:
            if f["criticidad"] not in selected_severities:
                continue
            with st.expander(f"{f['id']} · {f['criticidad']} · {f['categoria']} · {f['titulo']}", expanded=False):
                st.write("**Por qué se generó:**", f["justificacion"])
                st.write("**Siguiente verificación:**", f["recomendacion"])
                st.caption("Evidencias exactas de las filas del Excel: " + ", ".join(map(str, f["filas"])))
                st.dataframe(pd.DataFrame(f["evidencias"]), use_container_width=True, hide_index=True)
        st.download_button("⬇️ Descargar hallazgos estructurados (JSON)", data=json.dumps(findings, ensure_ascii=False, indent=2),
                           file_name="hallazgos_soc.json", mime="application/json")
    else:
        st.write("No hay hallazgos para revisar.")

with tab_dash:
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Casos correlacionados por criticidad**")
        by_severity = Counter(case["criticidad"] for case in cases)
        if by_severity:
            st.bar_chart(pd.DataFrame({"Casos":by_severity}))
        else:
            st.caption("No hay casos correlacionados.")
    with col2:
        st.markdown("**Casos por categoría**")
        by_category = Counter(case["categoria"] for case in cases)
        if by_category:
            st.bar_chart(pd.DataFrame({"Casos": by_category}))
        else:
            st.caption("No hay casos correlacionados.")
    with col1:
        st.markdown("**Alertas individuales por categoría**")
        freq = Counter(f["categoria"] for f in findings)
        if freq:
            st.bar_chart(pd.DataFrame({"Alertas": freq}).sort_values("Alertas", ascending=False))
        else:
            st.caption("No hay alertas individuales.")
    with col2:
        st.markdown("**Alertas individuales por criticidad**")
        sev = Counter(f["criticidad"] for f in findings)
        if sev:
            st.bar_chart(pd.DataFrame({"Alertas": sev}))
        else:
            st.caption("No hay alertas individuales.")
    st.markdown("**Actividad temporal de registros (intervalos de 15 minutos)**")
    dates = logs["dt"].dropna()
    if not dates.empty:
        try:
            timeline = pd.DataFrame({"dia": dates.dt.floor("15min")}).groupby("dia").size().rename("Registros")
            st.line_chart(timeline)
        except Exception:
            st.caption("No se pudieron agrupar fechas heterogéneas. Revisa su formato y zona horaria.")
    else:
        st.caption("No hay fechas legibles para crear una línea de tiempo.")
    if "log_source" in logs and logs["log_source"].ne("").any():
        st.markdown("**Volumen por fuente de registros**")
        st.bar_chart(logs["log_source"].value_counts())
    st.markdown("**Resumen tabulado**")
    if findings:
        st.dataframe(pd.DataFrame([{k: f[k] for k in ("id", "categoria", "criticidad", "titulo", "justificacion")} for f in findings]), use_container_width=True, hide_index=True)

with tab_reports:
    client = st.text_input("Nombre del cliente en los informes", value="Organización cliente - Estocolmo, Suecia", max_chars=120)
    st.markdown("**Dos documentos distintos:** el ejecutivo habla de impacto y decisiones; el técnico conserva metodología, reglas, evidencias y filas de origen.")
    with st.expander("🤖 IA gratuita · Gemini interpreta evidencias y ayuda a redactar"):
        st.info("**Sin pagos:** Gemini 3.5 Flash-Lite puede utilizarse dentro de la cuota gratuita de Google AI Studio. La disponibilidad y los límites dependen del proyecto. El motor SOC y los PDF funcionan incluso sin IA.")
        st.caption("Privacidad: se envían a Gemini únicamente estadísticas, tipos de eventos y referencias minimizadas; no se envía el Excel completo ni IP, usuarios, rutas o comandos literales. En el nivel gratuito, Google puede utilizar el contenido para mejorar sus productos. Usa solo datos académicos o autorizados.")
        def cloud_secret(name):
            try:
                return str(st.secrets.get(name, "")).strip()
            except Exception:
                return ""
        server_key = cloud_secret("GEMINI_API_KEY")
        server_pin = cloud_secret("SOC_AI_PIN")
        if server_key and server_pin:
            import hmac
            input_pin = st.text_input("Código de acceso a la IA (facilitado por quien administra la aplicación)", type="password", key="soc_gemini_pin")
            unlocked = bool(input_pin) and hmac.compare_digest(input_pin, server_pin)
            api_key = server_key if unlocked else ""
            st.caption("La clave API está guardada en los secretos privados del servidor y no se muestra aquí. Se requiere un código para evitar agotar la cuota gratuita públicamente.")
        else:
            if server_key and not server_pin:
                st.warning("Por seguridad, establece SOC_AI_PIN en Secrets de Streamlit antes de habilitar la clave compartida.")
            api_key = st.text_input("Clave GRATUITA de Google AI Studio (solo durante esta sesión)", type="password", value="", key="gemini_key_user")
            st.caption("Obtén una clave gratuita en https://aistudio.google.com/apikey . No la pegues en GitHub ni en el chat.")
        permission = st.checkbox("Autorizo enviar exclusivamente el resumen minimizado a Gemini; entiendo sus límites gratuitos y el tratamiento de datos del nivel gratuito.", key="gemini_consent")
        if st.button("✨ Interpretar los casos con Gemini (gratis)", disabled=not (api_key and permission), type="secondary"):
            if st.session_state.get("ai_request_count", 0) >= 3:
                st.warning("Alcanzaste el límite de 3 consultas en esta sesión para cuidar la cuota gratuita.")
            else:
                try:
                    from ai_helper import ai_report
                    with st.spinner("Gemini está interpretando un resumen minimizado de las evidencias..."):
                        narrative = ai_report(api_key, "gemini-3.5-flash-lite", summary, findings, cases)
                    st.session_state["ai_exec"] = narrative["ejecutivo"]
                    st.session_state["ai_tech"] = narrative["tecnico"]
                    st.session_state["ai_cases"] = {c["id"]: c for c in narrative["casos"]}
                    st.session_state["ai_request_count"] = st.session_state.get("ai_request_count", 0) + 1
                    st.success("Interpretaciones generadas. Verifica cada afirmación con los eventos antes de entregar.")
                except Exception as exc:
                    st.error(f"La IA no respondió. El análisis SOC y los PDF siguen disponibles. Motivo: {exc}")
    if st.session_state.get("ai_exec"):
        st.markdown("**🤖 Resumen ejecutivo asistido por IA (borrador, requiere revisión):**")
        st.write(st.session_state["ai_exec"])
    if st.session_state.get("ai_tech"):
        with st.expander("🤖 Interpretación técnica asistida por IA"):
            st.write(st.session_state["ai_tech"])
    if st.session_state.get("ai_cases"):
        st.markdown("#### 🤖 Interpretación caso por caso · Evidencias citadas")
        st.caption("Las referencias se verifican contra los eventos del caso; el contenido redactado por la IA requiere validación humana.")
        for case in cases:
            suggestion = st.session_state["ai_cases"].get(case["id"])
            if not suggestion:
                continue
            with st.expander(f"{case['id']} · {case['titulo']}"):
                st.write("**Interpretación:**", suggestion["interpretacion"])
                st.write("**Qué falta verificar:**", suggestion["que_falta_confirmar"])
                st.caption("Eventos citados: " + (", ".join(suggestion["referencias"]) or "No citó eventos verificables"))
    try:
        b1 = build_pdf("ejecutivo", summary, findings, limitations, client=client, ai_commentary=st.session_state.get("ai_exec", ""), cases=cases)
        b2 = build_pdf("tecnico", summary, findings, limitations, client=client, ai_commentary=st.session_state.get("ai_tech", ""), cases=cases)
        left, right = st.columns(2)
        with left:
            st.download_button("📥 Descargar informe EJECUTIVO (PDF)", data=b1, file_name="informe_ejecutivo_SOC.pdf", mime="application/pdf", use_container_width=True)
        with right:
            st.download_button("📥 Descargar informe TÉCNICO (PDF)", data=b2, file_name="informe_tecnico_SOC.pdf", mime="application/pdf", use_container_width=True)
        st.markdown("#### Informe unificado para entregar al curso")
        st.caption("Este PDF reúne una portada, el resumen ejecutivo y el informe técnico. Copia su enlace de Drive al formulario del curso después de subirlo.")
        url_app = st.text_input("Dirección pública de la aplicación (opcional, una vez publicada)", key="app_url", placeholder="https://tu-proyecto.streamlit.app")
        url_video = st.text_input("Enlace al video demostrativo (opcional)", key="video_url", placeholder="https://...")
        bundled_pdf = build_submission_pdf(b1, b2, client=client, cases=len(cases), app_url=url_app, video_url=url_video)
        st.download_button("📦 Descargar PDF FINAL UNIFICADO", data=bundled_pdf, file_name="SOC_Investigator_Entrega_Final.pdf", mime="application/pdf", type="primary", use_container_width=True)
    except Exception as exc:
        st.error(f"Error generando PDF: {exc}")

with tab_method:
    st.markdown("""
**Categorías cubiertas:** fuerza bruta, inicios sospechosos, actividad de privilegios, comandos y procesos, movimiento lateral y otras anomalías. Los casos correlacionados requieren señales complementarias.

**Reglas y alcance:**
- Fuerza bruta: múltiples fallos de autenticación para una identidad/IP en una ventana temporal.
- Inicio sospechoso: éxito tras varios fallos; revisión de horario y de IP cambiantes (sin concluir malicia).
- Escalamiento: registros de asignación/uso de privilegios o IDs de evento compatibles.
- Comandos: indicadores observables en texto de comando/evento.
- Movimiento lateral: eventos de acceso remoto compatibles, sin confirmarlo automáticamente.
- Otras anomalías: múltiples usuarios atacados desde la misma IP, o una cuenta con distintas IP.

**Riesgos de interpretación:** se necesita contexto del cliente, zona horaria, cuentas legítimas, red corporativa, MFA y cobertura de fuentes. No usa geolocalización inferida. No está conectado en tiempo real a un SIEM.
""")
    st.markdown("**Advertencias detectadas al procesar este archivo:**")
    for lim in limitations:
        st.write("• " + lim)
