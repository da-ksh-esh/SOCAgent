"""Downloadable artefacts: PDF report (reportlab) and tickets JSON."""
from __future__ import annotations

import io
import json
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Characters the built-in PDF fonts cannot draw.
_REPLACE = {"—": "-", "–": "-", "→": "->", "≥": ">=", "·": "|", "…": "...", "✓": "OK", "✗": "X"}


def _clean(text: str) -> str:
    for a, b in _REPLACE.items():
        text = text.replace(a, b)
    text = text.encode("latin-1", "ignore").decode("latin-1")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)


def markdown_to_pdf(*documents: str) -> bytes:
    """Render the simple markdown the automation agent writes (headings, lists, tables) to PDF."""
    styles = getSampleStyleSheet()
    flow = []
    for doc in documents:
        table: list[list[str]] = []
        for raw in doc.splitlines() + [""]:
            line = raw.rstrip()
            if line.startswith("|"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                if not all(set(c) <= {"-", ":"} for c in cells):
                    table.append(cells)
                continue
            if table:
                data = [[Paragraph(_clean(c), styles["BodyText"]) for c in row] for row in table]
                t = Table(data, repeatRows=1)
                t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e4e4e7")),
                                       ("VALIGN", (0, 0), (-1, -1), "TOP")]))
                flow += [t, Spacer(1, 4 * mm)]
                table = []
            if not line:
                flow.append(Spacer(1, 2 * mm))
            elif line.startswith("#"):
                level = len(line) - len(line.lstrip("#"))
                flow.append(Paragraph(_clean(line.lstrip("# ")), styles["Heading2" if level <= 4 else "Heading3"]))
            elif re.match(r"^(\d+\.|-)\s", line):
                flow.append(Paragraph(_clean(line), styles["BodyText"], bulletText=None))
            else:
                flow.append(Paragraph(_clean(line), styles["BodyText"]))
        flow.append(Spacer(1, 8 * mm))
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm,
                      bottomMargin=14 * mm, title="SOC triage report").build(flow)
    return buf.getvalue()


def tickets_json(tickets: dict) -> str:
    return json.dumps(list(tickets.values()), indent=2)
