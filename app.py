# app.py
from __future__ import annotations

import os
import io
import csv
import base64
from datetime import datetime, timezone, date
from functools import wraps
from werkzeug.security import safe_join
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    session,
    abort,
)
from werkzeug.utils import secure_filename

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader

from models import db, AdminUser, Trainer, Formation, FormationRecord


# -------------------------
# Helpers (time, filenames)
# -------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def safe_filename(s: str) -> str:
    import re
    import unicodedata

    s = (s or "").strip()
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s)
    return s.strip("_")


def image_reader_from_dataurl(data_url: str) -> ImageReader:
    if not data_url or not data_url.startswith("data:image/png;base64,"):
        raise ValueError("Signature invalide (format attendu: PNG base64).")
    raw = base64.b64decode(data_url.split(",", 1)[1])
    return ImageReader(io.BytesIO(raw))


def parse_date_or_today(s: str) -> date:
    if not s:
        return date.today()
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return date.today()


# -------------------------
# App factory
# -------------------------
def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    # À changer en prod
    app.secret_key = "CHANGE_ME_SECRET_KEY"

    # Admin non public (URL connue)
    app.config["ADMIN_PATH"] = "/panel-nrfablab"

    # PDF settings
    app.config["DEFAULT_CITY"] = "Nanterre"
    app.config["TITLE_BLUE"] = "#365F91"

    # DB
    os.makedirs(app.instance_path, exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "app.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Uploads
    app.config["UPLOAD_ROOT"] = os.path.join(app.root_path, "uploads")
    app.config["SIGNATURE_DIR"] = os.path.join(app.config["UPLOAD_ROOT"], "signatures")
    app.config["ATTESTATION_DIR"] = r"C:\Users\FabLabFormations\OneDrive - Cesi\Habilitations"

    os.makedirs(app.config["SIGNATURE_DIR"], exist_ok=True)
    os.makedirs(app.config["ATTESTATION_DIR"], exist_ok=True)

    db.init_app(app)
    with app.app_context():
        db.create_all()
        seed_defaults()

    admin_base = app.config["ADMIN_PATH"]

    # -------------------------
    # Auth helpers
    # -------------------------
    def current_admin() -> AdminUser | None:
        uid = session.get("admin_user_id")
        return AdminUser.query.get(uid) if uid else None

    def login_required(role: str | None = None):
        def dec(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                u = current_admin()
                if not u or not u.is_active:
                    session.clear()
                    return redirect(url_for("admin_login"))
                if role and u.role != role:
                    abort(403)
                return fn(*args, **kwargs)

            return wrapper

        return dec

    # -------------------------
    # File helper
    # -------------------------
    def abs_from_rel(rel_path: str) -> str:
        # rel_path expected like "uploads/xxx/yyy.png"
        rel_path = (rel_path or "").replace("\\", "/")
        return os.path.join(app.root_path, rel_path)

    # -------------------------
    # PDF helpers
    # -------------------------
    def wrap_text(c: canvas.Canvas, text: str, font: str, size: int, maxw: float) -> list[str]:
        c.setFont(font, size)
        out: list[str] = []
        for raw_line in (text or "").splitlines():
            line = raw_line.rstrip()
            if not line:
                out.append("")
                continue
            words = line.split()
            cur = ""
            for w in words:
                test = (cur + " " + w).strip()
                if c.stringWidth(test, font, size) <= maxw:
                    cur = test
                else:
                    if cur:
                        out.append(cur)
                    cur = w
            if cur:
                out.append(cur)
        return out

    def draw_section(c: canvas.Canvas, y: float, title: str, text: str) -> float:
        maxw = A4[0] - 40 * mm

        c.setFillColor(colors.HexColor(app.config["TITLE_BLUE"]))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, title)

        c.setFillColor(colors.black)
        y -= 8 * mm

        body = (text or "").strip() or "(Texte non défini.)"
        lines = wrap_text(c, body, "Helvetica", 11, maxw)
        c.setFont("Helvetica", 11)

        for line in lines:
            # simple page break safety
            if y < 105 * mm:
                c.showPage()
                y = A4[1] - 25 * mm
                c.setFillColor(colors.black)
                c.setFont("Helvetica", 11)
            c.drawString(20 * mm, y, line)
            y -= 6 * mm

        y -= 4 * mm
        return y
    def email_to_token(email: str) -> str:
        return email.strip().lower().replace("@", "_at_")

    def build_attestation_filename(prenom: str, nom: str, email: str, formation_nom: str, date_iso: str) -> str:
        # IMPORTANT: formation_nom doit déjà être "safe" (espaces -> _, pas de caractères Windows interdits)
        return f"{prenom}_{nom}__{email_to_token(email)}__{formation_nom}_{date_iso}.pdf"

    def build_attestation_dbname(prenom: str, nom: str, formation_nom: str, date_iso: str) -> str:
        return f"{prenom}_{nom}__{formation_nom}_{date_iso}.pdf"

    def generate_attestation_pdf(record: FormationRecord, sig_forme_img: ImageReader) -> str:
        # Filename DISK: prenom_nom__email_at_...__formation_date.pdf
        formation_part = safe_filename(record.formation.name)
        email_part = safe_filename(record.email.replace("@", "_at_"))
        date_part = record.date_formation.isoformat()

        pdf_name_disk = (
            f"{safe_filename(record.prenom)}_{safe_filename(record.nom)}"
            f"__{email_part}__{formation_part}_{date_part}.pdf"
        )

        # Filename DB: prenom_nom__formation_date.pdf  (sans email)
        pdf_name_db = (
            f"{safe_filename(record.prenom)}_{safe_filename(record.nom)}"
            f"_{formation_part}_{date_part}.pdf"
        )

        target_dir = app.config["ATTESTATION_DIR"]
        os.makedirs(target_dir, exist_ok=True)

        abs_pdf = os.path.join(target_dir, pdf_name_disk)


        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4

        # Logo (dimensions/position exactes comme ton exemple)
        logo_path = os.path.join(app.root_path, "static", "cesi_logo.png")
        if os.path.exists(logo_path):
            c.drawImage(
                logo_path,
                120 * mm,
                height - 40 * mm,
                width=100 * mm,
                height=50 * mm,
                preserveAspectRatio=True,
                mask="auto",
            )

        # Titre centré
        c.setFillColor(colors.HexColor("#365F91"))
        c.setFont("Helvetica", 24)
        y = height - 30 * mm
        c.drawCentredString(A4[0] / 2, y, "Habilitation :")
        y -= 10 * mm
        c.drawCentredString(A4[0] / 2, y, record.formation.name)

        c.setFillColor(colors.black)

        y -= 30 * mm
        y = draw_section(c, y, "Formation :", record.formation.formation_text)
        y = draw_section(c, y, "Engagement :", record.formation.engagement_text)

        # Table (comme ton exemple)
        table_top = 100 * mm
        left_x_header = 40 * mm
        col_w = (A4[0] - 40 * mm) / 2
        col_w2 = (A4[0] - 40 * mm) / 4

        c.setFont("Helvetica", 11)
        c.drawString(left_x_header, table_top, "Personne habilitée")
        c.drawString(left_x_header + col_w, table_top, "Formateur")

        y0 = table_top - 10 * mm
        left_x = 20 * mm

        c.setFont("Helvetica", 11)
        c.drawString(left_x, y0, "Nom")
        c.drawString(left_x + col_w, y0, "Nom")
        c.drawString(left_x + col_w2, y0, record.nom)
        c.drawString(left_x + col_w + col_w2, y0, record.trainer.last_name)

        y2 = y0 - 7 * mm
        c.drawString(left_x, y2, "Prénom")
        c.drawString(left_x + col_w, y2, "Prénom")
        c.drawString(left_x + col_w2, y2, record.prenom)
        c.drawString(left_x + col_w + col_w2, y2, record.trainer.first_name)

        y4 = y2 - 7 * mm
        c.drawString(left_x, y4, "Signature")
        c.drawString(left_x + col_w, y4, "Signature")

        box_y = 35 * mm
        box_h = 28 * mm
        box_w = col_w - 10 * mm
        c.rect(left_x, box_y, box_w, box_h, stroke=1, fill=0)
        c.rect(left_x + col_w, box_y, box_w, box_h, stroke=1, fill=0)

        # Signature habilité (en mémoire, non stockée)
        try:
            c.drawImage(
                sig_forme_img,
                left_x + 2 * mm,
                box_y + 2 * mm,
                width=box_w - 4 * mm,
                height=box_h - 4 * mm,
                preserveAspectRatio=True,
                mask="auto",
            )
        except Exception:
            pass

        # Signature formateur (stockée sur Trainer.signature_path)
        try:
            if record.trainer.signature_path:
                c.drawImage(
                    abs_from_rel(record.trainer.signature_path),
                    left_x + col_w + 2 * mm,
                    box_y + 2 * mm,
                    width=box_w - 4 * mm,
                    height=box_h - 4 * mm,
                    preserveAspectRatio=True,
                    mask="auto",
                )
        except Exception:
            pass

        # Pied
        c.setFont("Helvetica", 11)
        c.drawString(20 * mm, 18 * mm, f"Date :  {record.date_formation.strftime('%d/%m/%Y')}")
        c.drawString(90 * mm, 18 * mm, f"Fait à :  {app.config['DEFAULT_CITY']}")

        c.setFont("Helvetica", 9)
        c.drawString(
            20 * mm,
            10 * mm,
            "Cette habilitation peut être suspendue ou retirée en cas de non-respect des règles de sécurité.",
        )

        c.showPage()
        c.save()
        buf.seek(0)

        with open(abs_pdf, "wb") as f:
            f.write(buf.read())

        return pdf_name_db, pdf_name_disk


    def records_query(formation_id: str | None):
        q = FormationRecord.query.order_by(FormationRecord.created_at.desc())
        if formation_id:
            try:
                q = q.filter(FormationRecord.formation_id == int(formation_id))
            except ValueError:
                pass
        return q

    # -------------------------
    # PUBLIC
    # -------------------------
    @app.get("/")
    def form():
        trainers = (
            Trainer.query.filter_by(is_active=True)
            .order_by(Trainer.last_name.asc(), Trainer.first_name.asc())
            .all()
        )
        formations_db = Formation.query.filter_by(is_active=True).order_by(Formation.name.asc()).all()

        # On passe des dicts pour un tojson fiable côté template
        formations = [
            {
                "id": fo.id,
                "name": fo.name,
                "formation_text": fo.formation_text,
                "engagement_text": fo.engagement_text,
            }
            for fo in formations_db
        ]

        today_str = date.today().isoformat()
        return render_template("form.html", trainers=trainers, formations=formations, today_str=today_str)

    @app.post("/submit")
    def submit():
        nom = (request.form.get("nom") or "").strip()
        prenom = (request.form.get("prenom") or "").strip()
        email_ = (request.form.get("email") or "").strip()
        trainer_id = (request.form.get("trainer_id") or "").strip()
        formation_id = (request.form.get("formation_id") or "").strip()
        date_str = (request.form.get("date_formation") or "").strip()

        sig_forme = request.form.get("signature_forme") or ""
        access_code = (request.form.get("access_code") or "").strip()

        errors: list[str] = []

        if not formation_id.isdigit():
            errors.append("Formation invalide.")
        if not trainer_id.isdigit():
            errors.append("Intervenant invalide.")

        if not nom:
            errors.append("Nom obligatoire.")
        if not prenom:
            errors.append("Prénom obligatoire.")

        if not email_:
            errors.append("Email obligatoire.")
        else:
            eml = email_.lower()
            if not (eml.endswith("@cesi.fr") or eml.endswith("@viacesi.fr")):
                errors.append("Email obligatoire en @cesi.fr ou @viacesi.fr.")

        if len(sig_forme) < 50:
            errors.append("Signature de la personne habilitée obligatoire.")
        if not access_code:
            errors.append("Code intervenant obligatoire.")

        trainer = Trainer.query.get(int(trainer_id)) if trainer_id.isdigit() else None
        formation = Formation.query.get(int(formation_id)) if formation_id.isdigit() else None

        if not trainer or not trainer.is_active:
            errors.append("Intervenant invalide.")
        else:
            if not trainer.signature_path:
                errors.append("Signature de l'intervenant manquante (à enregistrer côté admin).")
            if not trainer.access_code_hash:
                errors.append("Code intervenant non configuré pour ce formateur.")
            elif not trainer.check_access_code(access_code):
                errors.append("Code intervenant incorrect.")

        if not formation or not formation.is_active:
            errors.append("Formation invalide.")

        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("form"))

        try:
            sig_forme_img = image_reader_from_dataurl(sig_forme)
        except Exception as ex:
            flash(f"Erreur signature: {ex}", "error")
            return redirect(url_for("form"))

        d = parse_date_or_today(date_str)

        record = FormationRecord(
            nom=nom,
            prenom=prenom,
            email=email_,
            trainer_id=trainer.id,
            formation_id=formation.id,
            date_formation=d,
        )

        # On ne stocke pas les signatures habilité/formateur au niveau record
        if hasattr(record, "signature_forme_path"):
            record.signature_forme_path = ""
        if hasattr(record, "signature_formateur_path"):
            record.signature_formateur_path = ""

        db.session.add(record)
        db.session.commit()

        pdf_name_db, pdf_name_disk = generate_attestation_pdf(record, sig_forme_img)

        # En DB : sans email
        record.attestation_pdf_path = pdf_name_db

        db.session.commit()


        return render_template("success.html", record=record)

    @app.get("/file/<path:relpath>")
    def get_file(relpath: str):
        relpath = (relpath or "").replace("\\", "/")
        if not relpath.startswith("uploads/"):
            abort(404)
        abs_path = os.path.join(app.root_path, relpath)
        if not os.path.isfile(abs_path):
            abort(404)
        return send_file(abs_path)
    @app.get("/attestation/<path:filename>")
    def get_attestation(filename):
        target_dir = app.config["ATTESTATION_DIR"]
        abs_path = os.path.join(target_dir, filename)

        # 1) si le nom existe tel quel
        if os.path.exists(abs_path):
            return send_file(abs_path, mimetype="application/pdf")

        # 2) sinon, on suppose que filename est le nom DB (sans email)
        #    on retrouve l'enregistrement correspondant, puis on reconstruit le nom DISK
        r = FormationRecord.query.filter_by(attestation_pdf_path=filename).first()
        if not r:
            abort(404)

        formation_part = safe_filename(r.formation.name)
        email_part = safe_filename(r.email.replace("@", "_at_"))
        date_part = r.date_formation.isoformat()

        disk_name = (
            f"{safe_filename(r.prenom)}_{safe_filename(r.nom)}"
            f"_{email_part}__{formation_part}_{date_part}.pdf"
        )

        abs_path2 = os.path.join(target_dir, disk_name)
        if not os.path.exists(abs_path2):
            abort(404)

        return send_file(abs_path2, mimetype="application/pdf")

    # -------------------------
    # ADMIN - Auth
    # -------------------------
    @app.get(admin_base + "/login")
    def admin_login():
        return render_template("admin_login.html", show_admin_nav=False)

    @app.post(admin_base + "/login")
    def admin_login_post():
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        u = AdminUser.query.filter_by(username=username).first()
        if u and u.is_active and u.check_password(password):
            session["admin_user_id"] = u.id
            return redirect(url_for("admin_list"))

        flash("Identifiants invalides.", "error")
        return redirect(url_for("admin_login"))

    @app.get(admin_base + "/logout")
    def admin_logout():
        session.clear()
        return redirect(url_for("admin_login"))

    # -------------------------
    # ADMIN - Main list
    # -------------------------
    @app.get(admin_base + "/")
    @login_required()
    def admin_list():
        formation_id = request.args.get("formation_id") or ""
        records = records_query(formation_id).all()

        formations = Formation.query.filter_by(is_active=True).order_by(Formation.name.asc()).all()

        return render_template(
            "admin_list.html",
            records=records,
            formations=formations,
            formation_filter=formation_id,
            admin=current_admin(),
            show_admin_nav=True,
        )

    # -------------------------
    # ADMIN - Password
    # -------------------------
    @app.get(admin_base + "/password")
    @login_required()
    def admin_password():
        return render_template("admin_password.html", admin=current_admin(), show_admin_nav=True)

    @app.post(admin_base + "/password")
    @login_required()
    def admin_password_post():
        admin = current_admin()
        if not admin:
            return redirect(url_for("admin_login"))

        cur = (request.form.get("current_password") or "").strip()
        new = (request.form.get("new_password") or "").strip()
        conf = (request.form.get("new_password_confirm") or "").strip()

        if not admin.check_password(cur):
            flash("Mot de passe actuel incorrect.", "error")
            return redirect(url_for("admin_password"))

        if len(new) < 8:
            flash("Le nouveau mot de passe doit faire au moins 8 caractères.", "error")
            return redirect(url_for("admin_password"))

        if new != conf:
            flash("La confirmation ne correspond pas.", "error")
            return redirect(url_for("admin_password"))

        admin.set_password(new)
        db.session.commit()
        flash("Mot de passe mis à jour.", "ok")
        return redirect(url_for("admin_list"))

    # -------------------------
    # ADMIN - Delete record
    # -------------------------
    @app.post(admin_base + "/delete/<int:record_id>")
    @login_required()
    def admin_delete(record_id: int):
        record = FormationRecord.query.get_or_404(record_id)

        # Supprimer le PDF si présent
        rel = (record.attestation_pdf_path or "").replace("\\", "/")
        if rel.startswith("uploads/"):
            abs_p = os.path.join(app.root_path, rel)
            try:
                if os.path.isfile(abs_p):
                    os.remove(abs_p)
            except Exception:
                pass

        db.session.delete(record)
        db.session.commit()

        flash("Enregistrement supprimé.", "ok")
        return redirect(url_for("admin_list"))

    # -------------------------
    # ADMIN - Export CSV
    # -------------------------
    @app.get(admin_base + "/export/csv")
    @login_required()
    def admin_export_csv():
        formation_id = request.args.get("formation_id") or ""
        recs = records_query(formation_id).all()

        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(
            [
                "id",
                "nom",
                "prenom",
                "email",
                "formateur_nom",
                "formateur_prenom",
                "formation",
                "date_formation",
                "created_at",
                "pdf",
            ]
        )
        for r in recs:
            w.writerow(
                [
                    r.id,
                    r.nom,
                    r.prenom,
                    r.email,
                    r.trainer.last_name,
                    r.trainer.first_name,
                    r.formation.name,
                    r.date_formation.isoformat(),
                    r.created_at.isoformat() if r.created_at else "",
                    r.attestation_pdf_path or "",
                ]
            )

        mem = io.BytesIO(out.getvalue().encode("utf-8"))
        mem.seek(0)
        suffix = formation_id if formation_id else "toutes"
        return send_file(
            mem,
            mimetype="text/csv; charset=utf-8",
            as_attachment=True,
            download_name=f"habilitations_{suffix}.csv",
        )

    # -------------------------
    # ROOT - Trainers (signature + code)
    # -------------------------
    def save_trainer_signature_dataurl(data_url: str, trainer_name: str) -> str:
        if not data_url or not data_url.startswith("data:image/png;base64,"):
            raise ValueError("Signature formateur invalide.")
        raw = base64.b64decode(data_url.split(",", 1)[1])

        rel_dir = os.path.join("uploads", "signatures", "trainers")
        abs_dir = os.path.join(app.root_path, rel_dir)
        os.makedirs(abs_dir, exist_ok=True)

        fname = f"trainer_{safe_filename(trainer_name)}_{int(utcnow().timestamp())}.png"
        abs_path = os.path.join(abs_dir, fname)
        with open(abs_path, "wb") as f:
            f.write(raw)

        return f"{rel_dir}/{fname}".replace("\\", "/")
    @app.get(admin_base + "/trainers/signature/<int:trainer_id>")
    @login_required(role="root")
    def admin_trainer_signature(trainer_id: int):
        t = Trainer.query.get_or_404(trainer_id)
        if not t.signature_path:
            abort(404)
        abs_path = abs_from_rel(t.signature_path)
        if not os.path.exists(abs_path):
            abort(404)
        return send_file(abs_path, mimetype="image/png")

    @app.get(admin_base + "/trainers")
    @login_required(role="root")
    def admin_trainers():
        trainers = Trainer.query.order_by(Trainer.last_name.asc(), Trainer.first_name.asc()).all()
        return render_template(
            "admin_trainers.html",
            trainers=trainers,
            admin=current_admin(),
            show_admin_nav=True,
        )

    @app.post(admin_base + "/trainers/create")
    @login_required(role="root")
    def admin_trainers_create():
        ln = (request.form.get("last_name") or "").strip()
        fn = (request.form.get("first_name") or "").strip()
        code = (request.form.get("access_code") or "").strip()
        sig = request.form.get("signature_dataurl") or ""

        if not ln or not fn:
            flash("Nom et prénom du formateur obligatoires.", "error")
            return redirect(url_for("admin_trainers"))
        if not code or len(code) < 4:
            flash("Code intervenant obligatoire (min 4 caractères).", "error")
            return redirect(url_for("admin_trainers"))
        if not sig or len(sig) < 50:
            flash("Signature intervenant obligatoire.", "error")
            return redirect(url_for("admin_trainers"))

        existing = Trainer.query.filter_by(last_name=ln, first_name=fn).first()
        if existing:
            flash("Ce formateur existe déjà.", "error")
            return redirect(url_for("admin_trainers"))

        t = Trainer(last_name=ln, first_name=fn, is_active=True)
        t.set_access_code(code)
        try:
            t.signature_path = save_trainer_signature_dataurl(sig, f"{fn}_{ln}")
        except Exception as ex:
            flash(f"Erreur signature formateur: {ex}", "error")
            return redirect(url_for("admin_trainers"))

        db.session.add(t)
        db.session.commit()

        flash("Formateur créé.", "ok")
        return redirect(url_for("admin_trainers"))

    @app.post(admin_base + "/trainers/update/<int:trainer_id>")
    @login_required(role="root")
    def admin_trainers_update(trainer_id: int):
        t = Trainer.query.get_or_404(trainer_id)

        ln = (request.form.get("last_name") or "").strip()
        fn = (request.form.get("first_name") or "").strip()
        code = (request.form.get("access_code") or "").strip()
        is_active = (request.form.get("is_active") or "off") == "on"
        sig_file = request.files.get("signature_file")

        if not ln or not fn:
            flash("Nom et prénom obligatoires.", "error")
            return redirect(url_for("admin_trainers"))

        other = Trainer.query.filter(
            Trainer.last_name == ln, Trainer.first_name == fn, Trainer.id != t.id
        ).first()
        if other:
            flash("Nom/prénom déjà utilisés par un autre formateur.", "error")
            return redirect(url_for("admin_trainers"))

        if code:
            if len(code) < 4:
                flash("Code intervenant min 4 caractères.", "error")
                return redirect(url_for("admin_trainers"))
            t.set_access_code(code)

        if sig_file and sig_file.filename:
            if not sig_file.filename.lower().endswith(".png"):
                flash("La signature doit être un PNG.", "error")
                return redirect(url_for("admin_trainers"))

            rel_dir = os.path.join("uploads", "signatures", "trainers")
            abs_dir = os.path.join(app.root_path, rel_dir)
            os.makedirs(abs_dir, exist_ok=True)

            fname = f"trainer_{safe_filename(fn+'_'+ln)}_{int(utcnow().timestamp())}.png"
            abs_path = os.path.join(abs_dir, fname)
            sig_file.save(abs_path)
            t.signature_path = f"{rel_dir}/{fname}".replace("\\", "/")

        t.last_name = ln
        t.first_name = fn
        t.is_active = is_active
        db.session.commit()

        flash("Formateur mis à jour.", "ok")
        return redirect(url_for("admin_trainers"))

    @app.post(admin_base + "/trainers/delete/<int:trainer_id>")
    @login_required(role="root")
    def admin_trainers_delete(trainer_id: int):
        t = Trainer.query.get_or_404(trainer_id)

        used = FormationRecord.query.filter_by(trainer_id=t.id).first()
        if used:
            t.is_active = False
            db.session.commit()
            flash("Formateur désactivé (utilisé dans des enregistrements).", "ok")
            return redirect(url_for("admin_trainers"))

        db.session.delete(t)
        db.session.commit()
        flash("Formateur supprimé.", "ok")
        return redirect(url_for("admin_trainers"))

    # -------------------------
    # ROOT - Formations
    # -------------------------
    @app.get(admin_base + "/formations")
    @login_required(role="root")
    def admin_formations():
        formations = Formation.query.order_by(Formation.name.asc()).all()
        return render_template(
            "admin_formations.html",
            formations=formations,
            admin=current_admin(),
            show_admin_nav=True,
        )

    @app.post(admin_base + "/formations/create")
    @login_required(role="root")
    def admin_formations_create():
        name = (request.form.get("name") or "").strip()
        ft = (request.form.get("formation_text") or "").strip()
        et = (request.form.get("engagement_text") or "").strip()

        if not name:
            flash("Nom de la formation obligatoire.", "error")
            return redirect(url_for("admin_formations"))
        if Formation.query.filter_by(name=name).first():
            flash("Cette formation existe déjà.", "error")
            return redirect(url_for("admin_formations"))

        f = Formation(name=name, formation_text=ft, engagement_text=et, is_active=True)
        db.session.add(f)
        db.session.commit()

        flash("Formation créée.", "ok")
        return redirect(url_for("admin_formations"))

    @app.post(admin_base + "/formations/update/<int:formation_id>")
    @login_required(role="root")
    def admin_formations_update(formation_id: int):
        f = Formation.query.get_or_404(formation_id)

        name = (request.form.get("name") or "").strip()
        ft = (request.form.get("formation_text") or "").strip()
        et = (request.form.get("engagement_text") or "").strip()
        is_active = (request.form.get("is_active") or "off") == "on"

        if not name:
            flash("Nom obligatoire.", "error")
            return redirect(url_for("admin_formations"))

        other = Formation.query.filter(Formation.name == name, Formation.id != f.id).first()
        if other:
            flash("Nom déjà utilisé par une autre formation.", "error")
            return redirect(url_for("admin_formations"))

        f.name = name
        f.formation_text = ft
        f.engagement_text = et
        f.is_active = is_active
        db.session.commit()

        flash("Formation mise à jour.", "ok")
        return redirect(url_for("admin_formations"))

    @app.post(admin_base + "/formations/delete/<int:formation_id>")
    @login_required(role="root")
    def admin_formations_delete(formation_id: int):
        f = Formation.query.get_or_404(formation_id)

        used = FormationRecord.query.filter_by(formation_id=f.id).first()
        if used:
            f.is_active = False
            db.session.commit()
            flash("Formation désactivée (utilisée dans des enregistrements).", "ok")
            return redirect(url_for("admin_formations"))

        db.session.delete(f)
        db.session.commit()
        flash("Formation supprimée.", "ok")
        return redirect(url_for("admin_formations"))

    # -------------------------
    # ROOT - Admin users
    # -------------------------
    @app.get(admin_base + "/admins")
    @login_required(role="root")
    def admin_admins():
        admins = AdminUser.query.order_by(AdminUser.role.desc(), AdminUser.username.asc()).all()
        return render_template(
            "admin_admins.html",
            admins=admins,
            admin=current_admin(),
            show_admin_nav=True,
        )

    @app.post(admin_base + "/admins/create")
    @login_required(role="root")
    def admin_admins_create():
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        role = (request.form.get("role") or "admin").strip()
        if role not in ("admin", "root"):
            role = "admin"

        if not username or not password:
            flash("Username et mot de passe obligatoires.", "error")
            return redirect(url_for("admin_admins"))
        if len(password) < 8:
            flash("Mot de passe min 8 caractères.", "error")
            return redirect(url_for("admin_admins"))
        if AdminUser.query.filter_by(username=username).first():
            flash("Username déjà utilisé.", "error")
            return redirect(url_for("admin_admins"))

        u = AdminUser(username=username, role=role, is_active=True)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        flash("Compte admin créé.", "ok")
        return redirect(url_for("admin_admins"))

    @app.post(admin_base + "/admins/update/<int:user_id>")
    @login_required(role="root")
    def admin_admins_update(user_id: int):
        u = AdminUser.query.get_or_404(user_id)

        role = (request.form.get("role") or u.role).strip()
        is_active = (request.form.get("is_active") or "off") == "on"
        new_password = (request.form.get("new_password") or "").strip()

        # Root intouchable
        if u.username == "root":
            role = "root"
            is_active = True

        if role not in ("admin", "root"):
            role = u.role

        u.role = role
        u.is_active = is_active

        if new_password:
            if len(new_password) < 8:
                flash("Nouveau mot de passe min 8 caractères.", "error")
                return redirect(url_for("admin_admins"))
            u.set_password(new_password)

        db.session.commit()
        flash("Compte admin mis à jour.", "ok")
        return redirect(url_for("admin_admins"))

    @app.post(admin_base + "/admins/delete/<int:user_id>")
    @login_required(role="root")
    def admin_admins_delete(user_id: int):
        u = AdminUser.query.get_or_404(user_id)

        if u.username == "root":
            flash("Impossible de supprimer le compte root.", "error")
            return redirect(url_for("admin_admins"))

        db.session.delete(u)
        db.session.commit()
        flash("Compte supprimé.", "ok")
        return redirect(url_for("admin_admins"))

    return app


# -------------------------
# Default seed
# -------------------------
def seed_defaults() -> None:
    if AdminUser.query.count() == 0:
        root = AdminUser(username="root", role="root", is_active=True)
        root.set_password("root123")  # change after first login
        db.session.add(root)
        db.session.commit()


if __name__ == "__main__":
    app = create_app()
    # LAN: host="0.0.0.0"
    app.run(host="0.0.0.0", port=5000, debug=True)
