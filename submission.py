"""Unifica los dos PDF auditables en una única entrega con portada profesional."""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from urllib.parse import urlparse

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen.canvas import Canvas

BACKGROUND = colors.HexColor('#0B1220')
MID = colors.HexColor('#132544')
BLUE = colors.HexColor('#4D8AFF')
MUTED = colors.HexColor('#B8C6DC')


def _verified_http_url(value: str) -> str:
    text = (value or '').strip()
    if len(text) > 500 or any(x in text for x in ('\n', '\r', '\x00')):
        return ''
    try:
        url = urlparse(text)
    except ValueError:
        return ''
    return text if url.scheme in ('https', 'http') and url.netloc and not url.username and not url.password else ''


def _cover(client: str, cases: int, app_url: str = '', video_url: str = '') -> bytes:
    buffer = BytesIO()
    canvas = Canvas(buffer, pagesize=A4)
    width, height = A4
    canvas.setFillColor(BACKGROUND)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)
    canvas.setFillColor(MID)
    canvas.roundRect(1.65*cm, 3.25*cm, width-3.3*cm, height-6.2*cm, 16, fill=1, stroke=0)
    canvas.setFillColor(BLUE)
    canvas.rect(1.9*cm, height-4.35*cm, 1.3*cm, 0.10*cm, fill=1, stroke=0)
    canvas.setFont('Helvetica-Bold', 13)
    canvas.setFillColor(BLUE)
    canvas.drawString(2.05*cm, height-5.5*cm, 'SOC INVESTIGATOR')
    canvas.setFillColor(colors.white)
    canvas.setFont('Helvetica-Bold', 25)
    canvas.drawString(2.05*cm, height-7.1*cm, 'Investigacion de posibles')
    canvas.drawString(2.05*cm, height-8.1*cm, 'incidentes de seguridad')
    canvas.setFont('Helvetica', 11)
    canvas.setFillColor(MUTED)
    canvas.drawString(2.05*cm, height-9.3*cm, 'Informe ejecutivo + informe tecnico')
    canvas.drawString(2.05*cm, height-9.95*cm, 'Evidencias y correlaciones desde una exportacion SIEM')
    canvas.setStrokeColor(colors.HexColor('#39516F'))
    canvas.line(2.05*cm, height-11.35*cm, width-2.05*cm, height-11.35*cm)
    canvas.setFont('Helvetica-Bold', 10)
    canvas.setFillColor(colors.white)
    canvas.drawString(2.05*cm, height-12.5*cm, 'CLIENTE / ESCENARIO')
    canvas.setFont('Helvetica', 10)
    canvas.setFillColor(MUTED)
    text = client.strip() or 'Organizacion cliente - Estocolmo, Suecia'
    canvas.drawString(2.05*cm, height-13.1*cm, text[:75])
    canvas.setFillColor(colors.white)
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(2.05*cm, height-14.45*cm, 'ALCANCE Y RESULTADOS')
    canvas.setFont('Helvetica', 10)
    canvas.setFillColor(MUTED)
    canvas.drawString(2.05*cm, height-15.15*cm, f'{cases} hipotesis de investigacion correlacionadas')
    canvas.drawString(2.05*cm, height-15.75*cm, 'Sin confirmacion forense automatica de compromiso')
    canvas.setFillColor(colors.white)
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(2.05*cm, height-17.1*cm, 'ACCESO A LA APLICACION')
    application = _verified_http_url(app_url)
    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(BLUE if application else MUTED)
    canvas.drawString(2.05*cm, height-17.75*cm, (application[:86] if application else 'Pendiente de publicacion: anadir URL al generar el PDF final'))
    if application:
        canvas.linkURL(application, (2.02*cm, height-18.02*cm, width-2.02*cm, height-17.5*cm), relative=0)
    video = _verified_http_url(video_url)
    if video:
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 10)
        canvas.drawString(2.05*cm, height-18.95*cm, 'VIDEO DEMOSTRATIVO')
        canvas.setFillColor(BLUE)
        canvas.setFont('Helvetica', 9)
        canvas.drawString(2.05*cm, height-19.55*cm, video[:86])
        canvas.linkURL(video, (2.02*cm, height-19.8*cm, width-2.02*cm, height-19.3*cm), relative=0)
    canvas.setFillColor(MUTED)
    canvas.setFont('Helvetica', 9)
    canvas.drawString(2.05*cm, 2.4*cm, f'Fecha de emision: {datetime.now().strftime("%d/%m/%Y")}')
    canvas.drawString(2.05*cm, 1.95*cm, 'Proyecto academico | Analisis reproducible y evidencia trazable')
    canvas.showPage()
    canvas.save()
    return buffer.getvalue()


def build_submission_pdf(executive: bytes, technical: bytes, client: str = 'Organizacion cliente - Estocolmo, Suecia',
                         cases: int = 0, app_url: str = '', video_url: str = '') -> bytes:
    """Portada + informe ejecutivo + informe tecnico, en ese orden."""
    writer = PdfWriter()
    for payload in (_cover(client, cases, app_url, video_url), executive, technical):
        reader = PdfReader(BytesIO(payload))
        for page in reader.pages:
            writer.add_page(page)
    writer.add_metadata({"/Title": "SOC Investigator - Entrega final", "/Subject": "Investigacion preliminar de incidentes SIEM"})
    result = BytesIO()
    writer.write(result)
    return result.getvalue()
