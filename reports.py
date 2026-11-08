"""Dos reportes distintos, basados en el mismo conjunto de hallazgos auditables."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape
from io import BytesIO
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak

FONT = "Helvetica"
BOLD = "Helvetica-Bold"
DEJAVU = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
DEJAVU_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
if os.path.isfile(DEJAVU) and os.path.isfile(DEJAVU_BOLD):
    pdfmetrics.registerFont(TTFont("DejaVuCustom", DEJAVU))
    pdfmetrics.registerFont(TTFont("DejaVuCustomBold", DEJAVU_BOLD))
    FONT, BOLD = "DejaVuCustom", "DejaVuCustomBold"

NAVY = colors.HexColor("#17132E")
BLUE = colors.HexColor("#8B5CF6")
MUTED = colors.HexColor("#58677A")
PALE = colors.HexColor("#F4F0FF")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("soc-title", parent=base["Title"], fontName=BOLD, fontSize=18, leading=25, textColor=NAVY, spaceAfter=13),
        "h2": ParagraphStyle("soc-h2", parent=base["Heading2"], fontName=BOLD, fontSize=11, leading=15, textColor=NAVY, spaceBefore=15, spaceAfter=7, keepWithNext=True),
        "body": ParagraphStyle("soc-body", parent=base["BodyText"], fontName=FONT, fontSize=8.8, leading=14, spaceAfter=8),
        "small": ParagraphStyle("soc-small", parent=base["BodyText"], fontName=FONT, fontSize=7.6, leading=11, spaceAfter=5),
        "muted": ParagraphStyle("soc-muted", parent=base["BodyText"], fontName=FONT, fontSize=8.3, leading=13, textColor=MUTED, spaceAfter=7),
        "header": ParagraphStyle("soc-th", parent=base["BodyText"], fontName=BOLD, fontSize=8, leading=11, textColor=colors.white),
        "cell": ParagraphStyle("soc-td", parent=base["BodyText"], fontName=FONT, fontSize=7.5, leading=11),
    }


def _p(text, style):
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _foot(c, doc):
    c.saveState()
    w, _ = doc.pagesize
    c.setStrokeColor(colors.HexColor("#CBD5E1"))
    c.line(1.7 * cm, 1.45 * cm, w - 1.7 * cm, 1.45 * cm)
    c.setFont(FONT, 7)
    c.setFillColor(MUTED)
    c.drawString(1.7 * cm, 1.14 * cm, "SOC Investigator | Investigación preliminar | Uso académico")
    c.drawRightString(w - 1.7 * cm, 1.14 * cm, f"Página {doc.page}")
    c.restoreState()


def _table(rows, widths, styles, header=True):
    matrix = [[_p(cell, styles["header"] if header and i == 0 else styles["cell"]) for cell in row] for i, row in enumerate(rows)]
    table = Table(matrix, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    ts = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
    ]
    if header:
        ts.extend([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F5FC")])])
    table.setStyle(TableStyle(ts))
    return table


def build_pdf(kind: str, summary: dict, findings: list[dict], limitations: list[str], client: str = "Organización cliente - Estocolmo, Suecia", ai_commentary: str = "", cases: list[dict] | None = None, author: str = "Nachly Acosta", course: str = "Bootcamp Analista SOC Nivel 2", organizers: str = "DOJO y WOSEC Panamá") -> bytes:
    if kind not in {"ejecutivo", "tecnico"}:
        raise ValueError("kind debe ser 'ejecutivo' o 'tecnico'")
    cases = cases or []
    styles = _styles()
    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=(21 * cm, 29.7 * cm), leftMargin=1.7 * cm, rightMargin=1.7 * cm, topMargin=1.8 * cm, bottomMargin=2 * cm, title="Informe SOC " + kind)
    story = []
    title = "Informe ejecutivo de seguridad" if kind == "ejecutivo" else "Informe técnico de investigación SOC"
    story.extend([
        _p(title, styles["title"]),
        _p(f"Cliente: {client} | Fecha de emisión: {datetime.now().strftime('%d/%m/%Y')}", styles["muted"]),
        _p(f"Elaborado por: {(author or 'No indicado').strip()} | Curso: {(course or 'No indicado').strip()}", styles["small"]),
        _p(f"Comunidades formadoras: {(organizers or 'No indicadas').strip()}", styles["small"]),
        _p("Origen: registros exportados desde un SIEM, recibidos en un archivo Excel. Alcance limitado al archivo suministrado.", styles["small"]),
        _p("Estado de la evaluación: INDICIOS AUTOMÁTICOS. No es una confirmación forense de compromiso.", styles["muted"]),
    ])
    story.append(_p("Resumen de resultados", styles["h2"]))
    story.append(_p(f"Casos de investigación multiseñal: {len(cases)}. Son hipótesis, no incidentes confirmados.", styles["body"]))
    stats = [
        ["Registros", "Alertas individuales", "Alertas altas/críticas", "Usuarios", "IP origen"],
        [str(summary.get("registros", 0)), str(summary.get("hallazgos", 0)), str(summary.get("altos", 0)), str(summary.get("usuarios", 0)), str(summary.get("ip_origen", 0))],
    ]
    story.append(_table(stats, [3.45 * cm] * 5, styles))
    story.append(_p("Los casos correlacionados y las alertas individuales pueden compartir registros; no deben sumarse como incidentes distintos.", styles["small"]))
    if kind == "ejecutivo":
        story.append(_p("Conclusión preliminar", styles["h2"]))
        if findings:
            story.append(_p(f"Se encontraron {len(findings)} patrones que ameritan revisión. La información disponible permite priorizar investigaciones, pero no basta por sí sola para demostrar si ocurrió un incidente confirmado ni cuántos incidentes distintos hubo.", styles["body"]))
        else:
            story.append(_p("No se detectaron coincidencias con las reglas implementadas. Esto no permite descartar un incidente: pueden faltar fuentes, campos o comportamientos fuera de las reglas.", styles["body"]))
        if cases:
            story.append(_p("Investigaciones prioritarias", styles["h2"]))
            case_rows = [["Caso / criticidad", "Descripción", "Qué falta comprobar"]]
            for c in cases:
                case_rows.append([f"{c['id']} | {c['criticidad']}", c['titulo'], c['recomendacion']])
            story.append(_table(case_rows, [3.5 * cm, 6.1 * cm, 7.65 * cm], styles))
            story.append(_p("Estos escenarios pueden representar distintos incidentes o actividades autorizadas. El número definitivo requiere investigación y validación humana.", styles["body"]))
        counts = Counter((f["categoria"], f["criticidad"]) for f in findings)
        story.append(_p("Qué se observó en las alertas individuales", styles["h2"]))
        if counts:
            rows = [["Tipo de señal", "Nivel", "Detecciones"]] + [[cat, sev, str(n)] for (cat, sev), n in counts.items()]
            story.append(_table(rows, [8.0 * cm, 5.0 * cm, 4.25 * cm], styles))
        else:
            story.append(_p("No se identificaron señales de las categorías configuradas.", styles["body"]))
        story.append(_p("Acciones recomendadas", styles["h2"]))
        suggestions = list(dict.fromkeys(f["recomendacion"] for f in findings))[:6]
        if not suggestions:
            suggestions = ["Completar los registros disponibles, confirmar cobertura de las fuentes y validar las hipótesis con el equipo del cliente."]
        for n, rec in enumerate(suggestions, 1):
            story.append(_p(f"{n}. {rec}", styles["body"]))
        if ai_commentary:
            story.append(_p("Comentario de IA (pendiente de revisión humana)", styles["h2"]))
            story.append(_p(ai_commentary[:7000], styles["body"]))
    else:
        story.append(_p("Metodología y alcance", styles["h2"]))
        story.append(_p("Se leyeron las filas del Excel, se mapearon columnas de tiempo, usuario, IP, evento y otros campos cuando estaban disponibles, y se aplicaron reglas deterministas. Se correlacionaron inicios fallidos/exitosos por identidad y ventana temporal. Cada hallazgo incluye filas originales como referencia auditable.", styles["body"]))
        story.append(_p("Casos correlacionados y evidencia primaria", styles["h2"]))
        story.append(_p("En las tablas se muestran eventos de muestra. Para cada caso se conservan las referencias a todas las filas del Excel enumeradas en el texto; la evidencia completa puede consultarse en la aplicación.", styles["small"]))
        if not cases:
            story.append(_p("No se identificaron cadenas multiseñal con las reglas activas.", styles["body"]))
        for c in cases:
            story.append(_p(f"{c['id']} | {c['titulo']} | {c['criticidad']}", styles["h2"]))
            story.append(_p(f"Estado: {c['estado']} | Grado de certeza: {c['confianza']}", styles["small"]))
            story.append(_p(f"Correlación: {c['justificacion']}", styles["body"]))
            story.append(_p(f"Referencias: {len(c['filas'])} filas originales. Filas de Excel: {', '.join(map(str,c['filas'][:35]))}{' ...' if len(c['filas']) > 35 else ''}", styles["small"]))
            events = (c['evidencias'][:6] + c['evidencias'][-6:]) if len(c['evidencias']) > 12 else c['evidencias']
            if events:
                story.append(_p(f"Muestra de evidencia: {len(events)} de {len(c['evidencias'])} eventos relacionados. Las referencias completas están arriba.", styles["small"]))
                matrix = [["Fila / ID / hora", "Cuenta e IP / host", "Evento, destino y proceso"]]
                for event in events:
                    desc = " | ".join(filter(None, [str(event.get("event_id", "")) + ": " + str(event.get("event", "")), str(event.get("dest_host", "")), str(event.get("command", ""))]))
                    # Limitar un extracto individual no significa eliminar la referencia: el evento completo permanece en Excel.
                    if len(desc) > 390:
                        desc = desc[:390] + " ... [extracto; consultar Excel]"
                    matrix.append([f"{event.get('excel_row', '')} | {event.get('log_id','')} | {str(event.get('timestamp',''))[11:19]}",
                                   " | ".join(filter(None, [str(event.get('user', '')), str(event.get('src_ip', '')), str(event.get('host', ''))])),
                                   desc])
                story.append(_table(matrix, [4.0*cm,5.8*cm,7.45*cm], styles))
            story.append(_p(f"Siguiente verificación: {c['recomendacion']}", styles["body"]))
        story.append(_p("Alertas individuales complementarias", styles["h2"]))
        if not findings:
            story.append(_p("No hay hallazgos con las reglas disponibles. Revisar cobertura del archivo y límites señalados abajo.", styles["body"]))
        for f in findings:
            content = [
                _p(f"{f['id']} | {f['titulo']} | {f['criticidad']}", styles["h2"]),
                _p(f"Categoría: {f['categoria']}", styles["small"]),
                _p(f"Fundamento: {f['justificacion']}", styles["body"]),
                _p(f"Filas del Excel: {', '.join(map(str, f['filas'][:25]))}{'...' if len(f['filas']) > 25 else ''}", styles["small"]),
            ]
            story.extend(content)
            records = f["evidencias"][:12]
            if records:
                story.append(_p(f"Muestra de eventos: {len(records)} de {len(f['evidencias'])} registros relacionados.", styles["small"]))
                matrix = [["Fila / fecha", "Usuario / IP / equipo", "Evento / ID / comando"]]
                for e in records:
                    desc = " | ".join(filter(None, [str(e.get('evento', '')), "ID: " + str(e.get('id_evento', '')), str(e.get('comando', ''))]))
                    if len(desc) > 390:
                        desc = desc[:390] + " ... [extracto; consultar Excel]"
                    matrix.append([
                        f"{e.get('fila', '')} | {str(e.get('fecha', ''))[:25]}",
                        " | ".join(filter(None, [str(e.get('usuario', '')), str(e.get('ip', '')), str(e.get('equipo', '')), str(e.get('destino', ''))])),
                        desc,
                    ])
                story.append(_table(matrix, [3.7 * cm, 5.7 * cm, 7.85 * cm], styles))
            story.append(Spacer(1, 0.18 * cm))
            story.append(_p(f"Acción sugerida: {f['recomendacion']}", styles["body"]))
        if ai_commentary:
            story.append(_p("Interpretación asistida por IA (revisión humana requerida)", styles["h2"]))
            story.append(_p(ai_commentary[:12000], styles["body"]))
    story.append(_p("Limitaciones y grado de certeza", styles["h2"]))
    for limitation in limitations:
        story.append(_p("• " + limitation, styles["small"]))
    story.append(_p("Validación: el analista debe cotejar registros fuente, contexto operativo y alcance antes de elevar un hallazgo a incidente confirmado.", styles["muted"]))
    doc.build(story, onFirstPage=_foot, onLaterPages=_foot)
    return output.getvalue()
