"""Личные анкеты и комплекты документов."""

from io import BytesIO
import json

from flask import Blueprint, abort, flash, g, redirect, render_template, request, send_file, url_for
from PIL import Image, UnidentifiedImageError

from .db import get_db
from .personal_history import history_page
from .threat_model import (
    BY_STEP,
    CAT,
    CONCLUSIONS,
    CONSEQUENCES,
    DEFAULT,
    FIELDS,
    LABELS,
    RANK,
    REQUIRED,
    STEPS,
    XML_INVALID,
    assess,
    check_step,
    clean,
    conclusions,
    profile,
)
from .threat_model.documents import archive, selected_documents
from .threat_model.workbook import read_workbook, workbook

bp = Blueprint("threats", __name__, url_prefix="/threats")


def init_db(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS threat_models(
        id INTEGER PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL, data TEXT NOT NULL, stage INTEGER NOT NULL DEFAULT 1,
        revision INTEGER NOT NULL DEFAULT 1, diagram BLOB, output BLOB,
        updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS threats_owner ON threat_models(owner,updated);
    """)


def mine(model_id):
    row = (
        get_db()
        .execute(
            "SELECT id,name,data,stage,revision,diagram IS NOT NULL AS has_image,output IS NOT NULL AS ready "
            "FROM threat_models WHERE id=? AND owner=?",
            (model_id, g.user["id"]),
        )
        .fetchone()
    )
    if not row:
        abort(404)
    return row


def change(row, columns, args):
    db = get_db()
    submitted = request.form.get("revision", type=int)
    if submitted != row["revision"]:
        abort(409, description="Анкета изменилась в другой вкладке. Откройте свежую версию.")
    changed = db.execute(
        f"UPDATE threat_models SET {columns}, revision=revision+1, updated=CURRENT_TIMESTAMP "
        "WHERE id=? AND owner=? AND revision=?",
        (*args, row["id"], g.user["id"], submitted),
    )
    if not changed.rowcount:
        abort(409, description="Анкета изменилась. Повторите действие с новой версией.")
    db.commit()


@bp.get("/")
def index():
    return wizard(None, dict(DEFAULT), 1)


def import_sheet(data):
    uploaded = request.files.get("sheet")
    if not uploaded or not uploaded.filename:
        raise ValueError("Выберите заполненную анкету в формате Excel (.xlsx).")
    data.update(read_workbook(uploaded.stream.read(2_000_001)))


@bp.post("/new")
def new():
    data = dict(DEFAULT)
    stage = 1
    try:
        if "objectType" in request.form:
            update_step(1, data)
        if request.form.get("action") == "import" or request.files.get("sheet"):
            import_sheet(data)
        elif request.form.get("action") == "next":
            check_step(data, 1)
            stage = 2
    except ValueError as exc:
        return wizard(None, data, 1, str(exc))
    db = get_db()
    cursor = db.execute(
        "INSERT INTO threat_models(owner,name,data,stage) VALUES(?,?,?,?)",
        (
            g.user["id"],
            data.get("infosystemShortName") or "Новая анкета",
            json.dumps(data, ensure_ascii=False),
            stage,
        ),
    )
    db.commit()
    return redirect(url_for(".edit", model_id=cursor.lastrowid, step=stage))


@bp.get("/questionnaire.xlsx")
def blank():
    return send_file(workbook(DEFAULT), as_attachment=True, download_name="Анкета IS Manager.xlsx")


@bp.get("/<int:model_id>/questionnaire.xlsx")
def export(model_id):
    return send_file(
        workbook(json.loads(mine(model_id)["data"])),
        as_attachment=True,
        download_name="Анкета IS Manager.xlsx",
    )


def read_image(upload):
    raw = upload.stream.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("Размер схемы превышает 2 МБ.")
    try:
        with Image.open(BytesIO(raw), formats=["JPEG", "PNG"]) as img:
            if img.width * img.height > 8_000_000:
                raise ValueError("Схема превышает 8 мегапикселей.")
            img.thumbnail((1700, 1700))
            out = BytesIO()
            img.convert("RGB").save(out, format="JPEG", quality=86)
            return out.getvalue()
    except (OSError, UnidentifiedImageError, Image.DecompressionBombError) as error:
        raise ValueError("Выберите корректную схему PNG или JPEG.") from error


def update_step(step, data):
    for k in BY_STEP[step]:
        data[k] = clean(k, request.form.get(k, ""))
    if step == 1:
        data["flags"] = [k for k in CAT["significance"] if k in request.form.getlist("flags")]
    if step == 5:
        data["consequences"] = [k for k in CONSEQUENCES if k in request.form.getlist("consequences")]
    if step == 6:
        p = profile(data)
        data["actors"] = [
            k
            for k in CAT["violators"]
            if k in request.form.getlist("actors") and (k != "foreign_intelligence" or p["foreign"])
        ]
        data["goals"] = {
            k: [goal for i, goal in enumerate(v["goals"]) if str(i) in request.form.getlist("goal_" + k)]
            for k, v in CAT["violators"].items()
        }
    if step == 7:
        data.pop("decisions", None)
        defaults = conclusions(data)
        choices = {}
        for code, default in defaults.items():
            value = request.form.get(code, "")
            if value and value not in CONCLUSIONS:
                raise ValueError("Выберите допустимое решение по каждой угрозе.")
            if value and value != default:
                choices[code] = value
        data["decisions"] = choices
    if step == 9:
        notes = {}
        for k in CAT["measures"]:
            note = request.form.get("measure_" + k, "").strip()
            if len(note) > 512 or XML_INVALID.search(note):
                raise ValueError("Допустимая длина описания меры — 512 символов.")
            if note:
                notes[k] = note
        data["implementations"] = notes


@bp.route("/<int:model_id>/<int:step>", methods=["GET", "POST"])
def edit(model_id, step):
    row = mine(model_id)
    if step < 1 or step > 11:
        abort(404)
    if step > row["stage"]:
        return redirect(url_for(".edit", model_id=model_id, step=row["stage"]))
    data = json.loads(row["data"])
    error = None
    if request.method == "POST":
        if step == 11:
            abort(405)
        try:
            importing = step == 1 and request.form.get("action") == "import"
            if not importing or "objectType" in request.form:
                update_step(step, data)
            next_step = step
            if importing:
                import_sheet(data)
            elif "jump" in request.form:
                next_step = request.form.get("jump", type=int)
                if next_step is None or not 1 <= next_step <= row["stage"]:
                    abort(400)
            elif request.form.get("action") == "next":
                check_step(data, step)
                next_step = step + 1
            columns = "name=?,data=?,stage=?"
            changed_answers = json.loads(row["data"]) != data
            args = [
                data.get("infosystemShortName") or "Новая анкета",
                json.dumps(data, ensure_ascii=False),
                max(next_step, row["stage"]),
            ]
            if step == 4:
                upload = request.files.get("diagram")
                if upload and upload.filename:
                    args.append(read_image(upload))
                    columns += ",diagram=?"
                    changed_answers = True
                elif row["has_image"] and request.form.get("remove_diagram"):
                    columns += ",diagram=NULL"
                    changed_answers = True
            if changed_answers:
                columns += ",output=NULL"
            change(row, columns, args)
            if request.form.get("action") == "list":
                return redirect(url_for(".index"))
            if request.form.get("action") == "save":
                flash("Анкета сохранена.", "success")
            elif request.form.get("action") == "import":
                flash("Поля из Excel загружены.", "success")
            return redirect(url_for(".edit", model_id=model_id, step=next_step))
        except ValueError as exc:
            error = str(exc)
    return wizard(row, data, step, error)


def wizard(row, data, step, error=None):
    history = None if row else history_page("""SELECT id,name,stage,output IS NOT NULL AS ready
        FROM threat_models WHERE owner=? AND instr(casefold(name),?)>0
        ORDER BY updated DESC,id DESC LIMIT 51 OFFSET ?""")
    missing = []
    if error and request.form.get("action") == "next":
        missing = [key for key in BY_STEP[step] if key in REQUIRED and not data.get(key)]
    result = None
    try:
        result = assess(data)
    except ValueError as exc:
        if step in (9, 11):
            error = error or str(exc)
    return render_template(
        "threats/edit.html",
        row=row,
        history=history,
        data=data,
        fields=FIELDS,
        labels=LABELS,
        ranks=RANK,
        keys=BY_STEP[step],
        steps=STEPS,
        step=step,
        catalog=CAT,
        error=error,
        missing=missing,
        consequences=CONSEQUENCES,
        recommendations=profile(data),
        choices=CONCLUSIONS,
        defaults=conclusions({**data, "decisions": {}}) if step == 7 else {},
        result=result,
        docs=selected_documents(data),
    ), 422 if error and request.method == "POST" else 200


@bp.post("/<int:model_id>/generate")
def generate(model_id):
    row = mine(model_id)
    data = json.loads(row["data"])
    if row["stage"] < 11:
        abort(400, description="Завершите анкету.")
    if request.form.get("revision", type=int) != row["revision"]:
        abort(409, description="Откройте сохранённую версию анкеты.")
    for step in range(1, 11):
        try:
            check_step(data, step)
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for(".edit", model_id=model_id, step=step))
    diagram = (
        get_db()
        .execute("SELECT diagram FROM threat_models WHERE id=? AND owner=?", (model_id, g.user["id"]))
        .fetchone()[0]
    )
    change(row, "output=?", [archive(data, diagram)])
    return redirect(url_for(".edit", model_id=model_id, step=11))


@bp.get("/<int:model_id>/documents.zip")
def download(model_id):
    row = (
        get_db()
        .execute("SELECT output FROM threat_models WHERE id=? AND owner=?", (model_id, g.user["id"]))
        .fetchone()
    )
    if not row or not row[0]:
        abort(404)
    return send_file(BytesIO(row[0]), as_attachment=True, download_name="Документы IS Manager.zip")


@bp.post("/<int:model_id>/delete")
def delete(model_id):
    db = get_db()
    deleted = db.execute(
        "DELETE FROM threat_models WHERE id=? AND owner=? AND revision=?",
        (model_id, g.user["id"], request.form.get("revision", type=int)),
    )
    if not deleted.rowcount:
        mine(model_id)
        abort(409, description="Анкета изменилась. Откройте сохранённую версию.")
    db.commit()
    return redirect(url_for(".index"))
