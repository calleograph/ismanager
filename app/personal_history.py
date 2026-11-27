"""Bound results and apply the same search controls to each browser's materials."""
from flask import g, request

from .db import get_db


def history_page(sql):
    query = request.args.get("q", "").strip()[:160]
    page = min(1000000, max(1, request.args.get("page", 1, type=int)))
    rows = get_db().execute(sql, (g.user["id"], query.casefold(), (page - 1) * 50)).fetchall()
    return dict(rows=rows[:50], query=query, page=page, more=len(rows) > 50)
