"""Portada profesional + informes originales, sin alterar evidencias ni conclusiones.

El enlace público del proyecto se incorpora automáticamente cuando no se especifica otro.
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
import os
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas

# Aplicación pública confirmada para este proyecto académico.
DEFAULT_APP_URL = "https://soc-investigator-siem.streamlit.app"
DARK = colors.HexColor('#0B1020')
PANEL = colors.HexColor('#1E1B36')
PURPLE = colors.HexColor('#A78BFA')
MUTED = colors.HexColor('#D1D5DB')
WHITE = colors.white

FONT, BOLD = 'Helvetica', 'Helvetica-Bold'
REGULAR_PATH = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD_PATH = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
if os.path.isfile(REGULAR_PATH) and os.path.isfile(BOLD_PATH):
    if 'SocDejaVuRegular' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('SocDejaVuRegular', REGULAR_PATH))
    if 'SocDejaVuBold' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('SocDejaVuBold', BOLD_PATH))
    FONT, BOLD = 'SocDejaVuRegular', 'SocDejaVuBold'


def _verified_http_url(value: str) -> str:
    text = (value or '').strip()
    if len(text) > 500 or any(x in text for x in ('\n', '\r', '\x00')):
        return ''
    try:
        url = urlparse(text)
    except ValueError:
        return ''
    return text if url.scheme in ('https', 'http') and url.netloc and not url.username and not url.password else ''


def _fit_line(c: Canvas, value: str, max_width: float, font_name: str, font_size: float) -> str:
    """Evita desbordes y nunca cambia la URL subyacente del enlace."""
    text = str(value)
    while text and pdfmetrics.stringWidth(text, font_name, font_size) > max_width:
        text = text[:-1]
    if text != value and text:
        text = text[:-1] + '…'
    return text


def _cover(client: str, cases: int, app_url: str = '', video_url: str = '') -> bytes:
    output = BytesIO()
    c = Canvas(output, pagesize=A4, pageCompression=1)
    width, height = A4
    m = 2.05 * cm
    inner_width = width - 2*m
    c.setTitle('SOC Investigator - Informe final')
    c.setFillColor(DARK)
    c.rect(0, 0, width, height, fill=1, stroke=0)
    c.setFillColor(PANEL)
    c.roundRect(1.35*cm, 2.9*cm, width-2.7*cm, height-5.2*cm, 14, fill=1, stroke=0)

    c.setStrokeColor(PURPLE)
    c.setLineWidth(4)
    c.line(m, height-4.5*cm, m+3.1*cm, height-4.5*cm)
    c.setFillColor(PURPLE)
    c.setFont(BOLD, 13)
    c.drawString(m, height-5.95*cm, 'SOC INVESTIGATOR')

    c.setFillColor(WHITE)
    c.setFont(BOLD, 21)
    c.drawString(m, height-8.2*cm, 'Investigación de posibles')
    c.drawString(m, height-9.22*cm, 'incidentes de seguridad')
    c.setFillColor(MUTED)
    c.setFont(FONT, 10.5)
    c.drawString(m, height-10.45*cm, 'Informe ejecutivo + informe técnico')
    c.drawString(m, height-11.05*cm, 'Correlación de eventos y evidencias trazables desde Excel')

    c.setStrokeColor(colors.HexColor('#4B4568'))
    c.setLineWidth(.75)
    c.line(m, height-12.30*cm, width-m, height-12.30*cm)

    def heading(y: float, label: str):
        c.setFillColor(PURPLE)
        c.setFont(BOLD, 9.2)
        c.drawString(m, y, label)

    heading(height-13.45*cm, 'CLIENTE / ESCENARIO')
    c.setFillColor(WHITE)
    c.setFont(FONT, 9.3)
    name = (client or '').strip() or 'Organización cliente - Estocolmo, Suecia'
    c.drawString(m, height-14.15*cm, _fit_line(c, name, inner_width, FONT, 9.3))

    heading(height-15.35*cm, 'ALCANCE')
    c.setFillColor(MUTED)
    c.setFont(FONT, 9.1)
    c.drawString(m, height-16.05*cm, f'{cases} casos correlacionados (hipótesis por validar)')
    c.drawString(m, height-16.75*cm, 'No es una confirmación forense de compromiso')

    heading(height-18.05*cm, 'APLICACIÓN WEB')
    app_link = _verified_http_url(app_url) or DEFAULT_APP_URL
    c.setFillColor(WHITE)
    c.setFont(BOLD, 9.1)
    c.drawString(m, height-18.75*cm, _fit_line(c, app_link, inner_width, BOLD, 9.1))
    c.linkURL(app_link, (m, height-19.0*cm, width-m, height-18.45*cm), relative=0, thickness=0)

    video = _verified_http_url(video_url)
    if video:
        heading(height-20.05*cm, 'VIDEO DEMOSTRATIVO')
        c.setFillColor(WHITE)
        c.setFont(FONT, 8.7)
        c.drawString(m, height-20.7*cm, _fit_line(c, video, inner_width, FONT, 8.7))
        c.linkURL(video, (m, height-20.9*cm, width-m, height-20.45*cm), relative=0, thickness=0)

    c.setFillColor(MUTED)
    c.setFont(FONT, 8)
    try:
        when = datetime.now(ZoneInfo('Europe/Stockholm'))
    except Exception:
        when = datetime.now()
    c.drawString(m, 2.08*cm, 'Proyecto académico | Análisis reproducible | Revisión humana')
    c.drawRightString(width-m, 1.58*cm, f'Emisión: {when.strftime("%d/%m/%Y")}')
    c.showPage()
    c.save()
    return output.getvalue()


def build_submission_pdf(executive: bytes, technical: bytes, client: str = 'Organización cliente - Estocolmo, Suecia',
                         cases: int = 0, app_url: str = '', video_url: str = '') -> bytes:
    """Portada + informe ejecutivo + informe técnico, en ese orden."""
    writer = PdfWriter()
    for payload in (_cover(client, cases, app_url, video_url), executive, technical):
        reader = PdfReader(BytesIO(payload))
        for page in reader.pages:
            writer.add_page(page)
    writer.add_metadata({
        '/Title': 'SOC Investigator - Entrega final',
        '/Subject': 'Investigación preliminar de posibles incidentes SIEM',
        '/Keywords': 'SOC, SIEM, investigación, seguridad, informe ejecutivo, informe técnico'
    })
    result = BytesIO()
    writer.write(result)
    return result.getvalue()
