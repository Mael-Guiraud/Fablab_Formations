from __future__ import annotations
import os, io, csv, base64, ssl, smtplib
from datetime import datetime, timezone, date
from functools import wraps
from email.message import EmailMessage

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, abort
from werkzeug.utils import secure_filename

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import colors

from models import db, AdminUser, Trainer, Formation, FormationRecord

def utcnow(): return datetime.now(timezone.utc)

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.secret_key = "CHANGE_ME_SECRET_KEY"
    app.config["ADMIN_PATH"] = "/panel-nrfablab"
    app.config["DEFAULT_CITY"] = "Nanterre"
    app.config["TITLE_BLUE"] = "#365F91"

    app.config["SMTP_HOST"] = "mail.mailo.com"
    app.config["SMTP_PORT"] = 465
    app.config["SMTP_USER"] = "nrfablab@mailo.com"
    app.config["SMTP_PASS"] = "TON_MOT_DE_PASSE_MAILO"
    app.config["SMTP_FROM"] = "nrfablab@mailo.com"

    os.makedirs(app.instance_path, exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "app.db")
    print(app.config["SQLALCHEMY_DATABASE_URI"])
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["UPLOAD_ROOT"] = os.path.join(app.root_path, "uploads")
    app.config["SIGNATURE_DIR"] = os.path.join(app.config["UPLOAD_ROOT"], "signatures")
    app.config["ATTESTATION_DIR"] = os.path.join(app.config["UPLOAD_ROOT"], "attestations")
    os.makedirs(app.config["SIGNATURE_DIR"], exist_ok=True)
    os.makedirs(app.config["ATTESTATION_DIR"], exist_ok=True)

    db.init_app(app)
    with app.app_context():
        db.create_all()
        seed_defaults()

    def current_admin():
        uid = session.get("admin_user_id")
        return AdminUser.query.get(uid) if uid else None

    def login_required(role=None):
        def dec(fn):
            @wraps(fn)
            def w(*a, **k):
                u = current_admin()
                if not u or not u.is_active:
                    session.clear()
                    return redirect(url_for("admin_login"))
                if role and u.role != role:
                    abort(403)
                return fn(*a, **k)
            return w
        return dec

    def parse_date_or_today(s: str) -> date:
        if not s: return date.today()
        try: return datetime.strptime(s, "%Y-%m-%d").date()
        except ValueError: return date.today()

    def save_signature_dataurl(data_url: str, filename_base: str) -> str:
        if not data_url or not data_url.startswith("data:image/png;base64,"):
            raise ValueError("Signature invalide (format attendu: PNG base64).")
        raw = base64.b64decode(data_url.split(",",1)[1])
        fname = f"{secure_filename(filename_base)}_{int(utcnow().timestamp())}.png"
        abs_path = os.path.join(app.config["SIGNATURE_DIR"], fname)
        with open(abs_path, "wb") as f: f.write(raw)
        return f"uploads/signatures/{fname}"

    def abs_from_rel(rel_path: str) -> str:
        return os.path.join(app.root_path, rel_path.replace('\\','/'))

    def wrap_text(c, text, font, size, maxw):
        c.setFont(font, size)
        out=[]
        for raw_line in (text or "").splitlines():
            line = raw_line.rstrip()
            if not line: out.append(""); continue
            words=line.split()
            cur=""
            for w in words:
                test=(cur+" "+w).strip()
                if c.stringWidth(test, font, size) <= maxw: cur=test
                else:
                    if cur: out.append(cur)
                    cur=w
            if cur: out.append(cur)
        return out

    def draw_section(c, y, title, text):
        maxw = (A4[0] - 40*mm)
        c.setFillColor(colors.HexColor(app.config["TITLE_BLUE"]))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20*mm, y, title)
        c.setFillColor(colors.black)
        y -= 8*mm
        body=(text or "").strip() or "(Texte non défini.)"
        lines=wrap_text(c, body, "Helvetica", 11, maxw)
        c.setFont("Helvetica", 11)
        for line in lines:
            if y < 105*mm:
                c.showPage()
                y = A4[1] - 25*mm
                c.setFillColor(colors.black)
                c.setFont("Helvetica", 11)
            c.drawString(20*mm, y, line)
            y -= 6*mm
        y -= 4*mm
        return y

    def generate_attestation_pdf(record: FormationRecord) -> str:
        safe = secure_filename(f"{record.nom}_{record.prenom}_{record.formation.name}_{record.id}".replace(" ","_"))
        pdf_name = f"habilitation_{safe}.pdf"
        abs_pdf = os.path.join(app.config["ATTESTATION_DIR"], pdf_name)

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4

        logo_path = os.path.join(app.root_path, "static", "cesi_logo.png")
        if os.path.exists(logo_path):
            c.drawImage(logo_path, 120*mm, height-40*mm, width=100*mm, height=50*mm,
                        preserveAspectRatio=True, mask='auto')

        c.setFillColor(colors.HexColor("#365F91"))
        c.setFont("Helvetica", 24)
        y = height - 30*mm
        c.drawCentredString( A4[0] / 2,          # centre horizontal
                            y,   # position verticale
                            "Habilitation :")
        y -= 10*mm
        c.drawCentredString( A4[0] / 2,          # centre horizontal
                            y,   # position verticale
                            record.formation.name)
        y -= 30*mm
        y = draw_section(c, y, "Formation :", record.formation.formation_text)
        y = draw_section(c, y, "Engagement :", record.formation.engagement_text)

        table_top = 100*mm
        left_x = 40*mm
        col_w = (A4[0]-40*mm)/2
        col_w2 = (A4[0]-40*mm)/4

        c.setFont("Helvetica", 11)
        c.drawString(left_x, table_top, "Personne habilitée")
        c.drawString(left_x+col_w, table_top, "Formateur")

        y0 = table_top-10*mm
        left_x = 20*mm
        c.setFont("Helvetica", 11)
        c.drawString(left_x, y0, "Nom"); c.drawString(left_x+col_w, y0, "Nom")

        c.drawString(left_x+col_w2, y0, record.nom); c.drawString(left_x+col_w+col_w2, y0, record.trainer.last_name)

        y2 = y0-7*mm
        c.drawString(left_x, y2, "Prénom"); c.drawString(left_x+col_w, y2, "Prénom")

        y3 = y2-5*mm
        c.drawString(left_x+col_w2, y2, record.prenom); c.drawString(left_x+col_w+col_w2, y2, record.trainer.first_name)

        y4 = y3-7*mm
        c.drawString(left_x, y4, "Signature"); c.drawString(left_x+col_w, y4, "Signature")

        box_y = 35*mm
        box_h = 28*mm
        box_w = col_w - 10*mm
        c.rect(left_x, box_y, box_w, box_h, stroke=1, fill=0)
        c.rect(left_x+col_w, box_y, box_w, box_h, stroke=1, fill=0)

        try:
            c.drawImage(abs_from_rel(record.signature_forme_path), left_x+2*mm, box_y+2*mm,
                        width=box_w-4*mm, height=box_h-4*mm, preserveAspectRatio=True, mask='auto')
        except Exception: pass
        try:
            c.drawImage(abs_from_rel(record.signature_formateur_path), left_x+col_w+2*mm, box_y+2*mm,
                        width=box_w-4*mm, height=box_h-4*mm, preserveAspectRatio=True, mask='auto')
        except Exception: pass

        c.setFont("Helvetica", 11)
        c.drawString(20*mm, 18*mm, f"Date :  {record.date_formation.strftime('%d/%m/%Y')}")
        c.drawString(90*mm, 18*mm, f"Fait à :  {app.config['DEFAULT_CITY']}")
        c.setFont("Helvetica", 9)
        c.drawString(20*mm, 10*mm, "Cette habilitation peut être suspendue ou retirée en cas de non-respect des règles de sécurité.")

        c.showPage(); c.save()
        buf.seek(0)
        with open(abs_pdf, "wb") as f: f.write(buf.read())
        return f"uploads/attestations/{pdf_name}"

    def send_attestation_email(to_email: str, record: FormationRecord, pdf_abs_path: str) -> None:
        host=app.config.get("SMTP_HOST","")
        port=int(app.config.get("SMTP_PORT",0) or 0)
        user=app.config.get("SMTP_USER","")
        pwd=app.config.get("SMTP_PASS","")
        from_addr=app.config.get("SMTP_FROM", user)
        if not host or not port or not user or not pwd or not from_addr: return

        msg=EmailMessage()
        msg["Subject"]="Votre habilitation / attestation"
        msg["From"]=from_addr
        msg["To"]=to_email
        msg.set_content(
            f"Bonjour {record.prenom} {record.nom},\n\n"
            f"Veuillez trouver en pièce jointe votre habilitation.\n\n"
            f"Formation : {record.formation.name}\n"
            f"Formateur : {record.trainer.display_name()}\n"
            f"Date : {record.date_formation.strftime('%d/%m/%Y')}\n\n"
            f"Cordialement,\n"
        )
        with open(pdf_abs_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="pdf", filename=os.path.basename(pdf_abs_path))

        context=ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as s:
                s.login(user, pwd); s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo(); s.starttls(context=context); s.ehlo()
                s.login(user, pwd); s.send_message(msg)

    def records_query(formation_id):
        q = FormationRecord.query.order_by(FormationRecord.created_at.desc())
        if formation_id:
            try: q=q.filter(FormationRecord.formation_id==int(formation_id))
            except ValueError: pass
        return q

    # PUBLIC
    @app.get("/")
    def form():
        trainers = Trainer.query.filter_by(is_active=True).order_by(Trainer.last_name.desc(), Trainer.first_name.desc()).all()
        formations = Formation.query.filter_by(is_active=True).order_by(Formation.name.desc()).all()
        return render_template("form.html", trainers=trainers, formations=formations)

    @app.post("/submit")
    def submit():
        nom=(request.form.get("nom") or "").strip()
        prenom=(request.form.get("prenom") or "").strip()
        email_=(request.form.get("email") or "").strip()
        trainer_id=(request.form.get("trainer_id") or "").strip()
        formation_id=(request.form.get("formation_id") or "").strip()
        date_str=(request.form.get("date_formation") or "").strip()
        sig_forme=request.form.get("signature_forme") or ""
        sig_formateur=request.form.get("signature_formateur") or ""

        errors=[]
        if not nom: errors.append("Nom obligatoire.")
        if not prenom: errors.append("Prénom obligatoire.")
        if not email_: errors.append("Email obligatoire.")

        trainer = Trainer.query.get(int(trainer_id)) if trainer_id.isdigit() else None
        formation = Formation.query.get(int(formation_id)) if formation_id.isdigit() else None
        if not trainer or not trainer.is_active: errors.append("Formateur invalide.")
        if not formation or not formation.is_active: errors.append("Formation invalide.")
        if len(sig_forme) < 50: errors.append("Signature de la personne habilitée obligatoire.")
        if len(sig_formateur) < 50: errors.append("Signature du formateur obligatoire.")

        if errors:
            for e in errors: flash(e, "error")
            return redirect(url_for("form"))

        d = parse_date_or_today(date_str)
        try:
            sig_forme_path = save_signature_dataurl(sig_forme, f"sig_habilite_{nom}_{prenom}")
            sig_formateur_path = save_signature_dataurl(sig_formateur, f"sig_formateur_{nom}_{prenom}")
        except Exception as ex:
            flash(f"Erreur signature: {ex}", "error")
            return redirect(url_for("form"))

        record = FormationRecord(
            nom=nom, prenom=prenom, email=email_,
            trainer_id=trainer.id, formation_id=formation.id,
            date_formation=d,
            signature_forme_path=sig_forme_path,
            signature_formateur_path=sig_formateur_path,
        )
        db.session.add(record); db.session.commit()

        rel_pdf = generate_attestation_pdf(record)
        record.attestation_pdf_path = rel_pdf
        db.session.commit()
        """
        try: send_attestation_email(record.email, record, abs_from_rel(rel_pdf))
        except Exception as ex: flash(f"Envoi email impossible: {ex}", "error")
        """
        return render_template("success.html", record=record)

    @app.get("/file/<path:relpath>")
    def get_file(relpath):
        relpath = relpath.replace('\\','/')
        if not relpath.startswith("uploads/"): abort(404)
        abs_path = os.path.join(app.root_path, relpath)
        if not os.path.isfile(abs_path): abort(404)
        return send_file(abs_path)

    # ADMIN
    admin_base = app.config["ADMIN_PATH"]

    @app.get(admin_base + "/login")
    def admin_login():
        return render_template("admin_login.html", show_admin_nav=False)

    @app.post(admin_base + "/login")
    def admin_login_post():
        username=(request.form.get("username") or "").strip()
        password=(request.form.get("password") or "").strip()
        u = AdminUser.query.filter_by(username=username).first()
        if u and u.is_active and u.check_password(password):
            session["admin_user_id"]=u.id
            return redirect(url_for("admin_list"))
        flash("Identifiants invalides.", "error")
        return redirect(url_for("admin_login"))

    @app.get(admin_base + "/logout")
    def admin_logout():
        session.clear()
        return redirect(url_for("admin_login"))

    @app.get(admin_base + "/")
    @login_required()
    def admin_list():
        formation_id=request.args.get("formation_id") or ""
        records=records_query(formation_id).all()
        formations=Formation.query.filter_by(is_active=True).order_by(Formation.name.desc()).all()
        return render_template("admin_list.html", records=records, formations=formations, formation_filter=formation_id,
                               admin=current_admin(), show_admin_nav=True)

    @app.get(admin_base + "/password")
    @login_required()
    def admin_password():
        return render_template("admin_password.html", admin=current_admin(), show_admin_nav=True)

    @app.post(admin_base + "/password")
    @login_required()
    def admin_password_post():
        admin=current_admin()
        cur=(request.form.get("current_password") or "").strip()
        new=(request.form.get("new_password") or "").strip()
        conf=(request.form.get("new_password_confirm") or "").strip()
        if not admin.check_password(cur):
            flash("Mot de passe actuel incorrect.", "error"); return redirect(url_for("admin_password"))
        if len(new) < 8:
            flash("Le nouveau mot de passe doit faire au moins 8 caractères.", "error"); return redirect(url_for("admin_password"))
        if new != conf:
            flash("La confirmation ne correspond pas.", "error"); return redirect(url_for("admin_password"))
        admin.set_password(new); db.session.commit()
        flash("Mot de passe mis à jour.", "ok")
        return redirect(url_for("admin_list"))

    @app.get(admin_base + "/edit/<int:record_id>")
    @login_required()
    def admin_edit(record_id:int):
        record=FormationRecord.query.get_or_404(record_id)
        trainers=Trainer.query.filter_by(is_active=True).order_by(Trainer.last_name.desc(), Trainer.first_name.desc()).all()
        formations=Formation.query.filter_by(is_active=True).order_by(Formation.name.desc()).all()
        return render_template("admin_edit.html", record=record, trainers=trainers, formations=formations,
                               admin=current_admin(), show_admin_nav=True)

    @app.post(admin_base + "/edit/<int:record_id>")
    @login_required()
    def admin_edit_post(record_id:int):
        record=FormationRecord.query.get_or_404(record_id)
        nom=(request.form.get("nom") or "").strip()
        prenom=(request.form.get("prenom") or "").strip()
        email_=(request.form.get("email") or "").strip()
        trainer_id=(request.form.get("trainer_id") or "").strip()
        formation_id=(request.form.get("formation_id") or "").strip()
        date_str=(request.form.get("date_formation") or "").strip()
        if not nom or not prenom or not email_:
            flash("Nom, prénom et email sont obligatoires.", "error"); return redirect(url_for("admin_edit", record_id=record_id))
        trainer = Trainer.query.get(int(trainer_id)) if trainer_id.isdigit() else None
        formation = Formation.query.get(int(formation_id)) if formation_id.isdigit() else None
        if not trainer or not trainer.is_active or not formation or not formation.is_active:
            flash("Formateur/formation invalides.", "error"); return redirect(url_for("admin_edit", record_id=record_id))
        record.nom=nom; record.prenom=prenom; record.email=email_
        record.trainer_id=trainer.id; record.formation_id=formation.id
        record.date_formation=parse_date_or_today(date_str)
        db.session.commit()
        rel_pdf=generate_attestation_pdf(record); record.attestation_pdf_path=rel_pdf; db.session.commit()
        flash("Enregistrement mis à jour (PDF régénéré).", "ok")
        return redirect(url_for("admin_list"))

    @app.post(admin_base + "/delete/<int:record_id>")
    @login_required()
    def admin_delete(record_id:int):
        record=FormationRecord.query.get_or_404(record_id)
        def del_file(rel):
            if not rel: return
            abs_p=os.path.join(app.root_path, rel.replace('\\','/'))
            try:
                if os.path.isfile(abs_p): os.remove(abs_p)
            except Exception: pass
        del_file(record.signature_forme_path); del_file(record.signature_formateur_path); del_file(record.attestation_pdf_path)
        db.session.delete(record); db.session.commit()
        flash("Enregistrement supprimé.", "ok")
        return redirect(url_for("admin_list"))

    @app.get(admin_base + "/export/csv")
    @login_required()
    def admin_export_csv():
        formation_id=request.args.get("formation_id") or ""
        recs=records_query(formation_id).all()
        out=io.StringIO(); w=csv.writer(out)
        w.writerow(["id","nom","prenom","email","formateur_nom","formateur_prenom","formation","date_formation","created_at","pdf"])
        for r in recs:
            w.writerow([r.id,r.nom,r.prenom,r.email,r.trainer.last_name,r.trainer.first_name,r.formation.name,
                        r.date_formation.isoformat(), r.created_at.isoformat(), r.attestation_pdf_path or ""])
        mem=io.BytesIO(out.getvalue().encode("utf-8")); mem.seek(0)
        suffix = formation_id if formation_id else "toutes"
        return send_file(mem, mimetype="text/csv; charset=utf-8", as_attachment=True,
                         download_name=f"habilitations_{suffix}.csv")

    # ROOT: trainers
    @app.get(admin_base + "/trainers")
    @login_required(role="root")
    def admin_trainers():
        trainers=Trainer.query.order_by(Trainer.last_name.desc(), Trainer.first_name.desc()).all()
        return render_template("admin_trainers.html", trainers=trainers, admin=current_admin(), show_admin_nav=True)

    @app.post(admin_base + "/trainers/create")
    @login_required(role="root")
    def admin_trainers_create():
        ln=(request.form.get("last_name") or "").strip()
        fn=(request.form.get("first_name") or "").strip()
        if not ln or not fn:
            flash("Nom et prénom du formateur obligatoires.", "error"); return redirect(url_for("admin_trainers"))
        if Trainer.query.filter_by(last_name=ln, first_name=fn).first():
            flash("Ce formateur existe déjà.", "error"); return redirect(url_for("admin_trainers"))
        t=Trainer(last_name=ln, first_name=fn, is_active=True)
        db.session.add(t); db.session.commit()
        flash("Formateur créé.", "ok")
        return redirect(url_for("admin_trainers"))

    @app.post(admin_base + "/trainers/update/<int:trainer_id>")
    @login_required(role="root")
    def admin_trainers_update(trainer_id:int):
        t=Trainer.query.get_or_404(trainer_id)
        ln=(request.form.get("last_name") or "").strip()
        fn=(request.form.get("first_name") or "").strip()
        is_active=(request.form.get("is_active") or "off")=="on"
        if not ln or not fn:
            flash("Nom et prénom obligatoires.", "error"); return redirect(url_for("admin_trainers"))
        other=Trainer.query.filter(Trainer.last_name==ln, Trainer.first_name==fn, Trainer.id!=t.id).first()
        if other:
            flash("Nom/prénom déjà utilisés par un autre formateur.", "error"); return redirect(url_for("admin_trainers"))
        t.last_name=ln; t.first_name=fn; t.is_active=is_active
        db.session.commit()
        flash("Formateur mis à jour.", "ok")
        return redirect(url_for("admin_trainers"))

    @app.post(admin_base + "/trainers/delete/<int:trainer_id>")
    @login_required(role="root")
    def admin_trainers_delete(trainer_id:int):
        t=Trainer.query.get_or_404(trainer_id)
        used=FormationRecord.query.filter_by(trainer_id=t.id).first()
        if used:
            t.is_active=False; db.session.commit()
            flash("Formateur désactivé (utilisé dans des enregistrements).", "ok")
            return redirect(url_for("admin_trainers"))
        db.session.delete(t); db.session.commit()
        flash("Formateur supprimé.", "ok")
        return redirect(url_for("admin_trainers"))

    # ROOT: formations
    @app.get(admin_base + "/formations")
    @login_required(role="root")
    def admin_formations():
        formations=Formation.query.order_by(Formation.name.desc()).all()
        return render_template("admin_formations.html", formations=formations, admin=current_admin(), show_admin_nav=True)

    @app.post(admin_base + "/formations/create")
    @login_required(role="root")
    def admin_formations_create():
        name=(request.form.get("name") or "").strip()
        ft=(request.form.get("formation_text") or "").strip()
        et=(request.form.get("engagement_text") or "").strip()
        if not name:
            flash("Nom de la formation obligatoire.", "error"); return redirect(url_for("admin_formations"))
        if Formation.query.filter_by(name=name).first():
            flash("Cette formation existe déjà.", "error"); return redirect(url_for("admin_formations"))
        f=Formation(name=name, formation_text=ft, engagement_text=et, is_active=True)
        db.session.add(f); db.session.commit()
        flash("Formation créée.", "ok")
        return redirect(url_for("admin_formations"))

    @app.post(admin_base + "/formations/update/<int:formation_id>")
    @login_required(role="root")
    def admin_formations_update(formation_id:int):
        f=Formation.query.get_or_404(formation_id)
        name=(request.form.get("name") or "").strip()
        ft=(request.form.get("formation_text") or "").strip()
        et=(request.form.get("engagement_text") or "").strip()
        is_active=(request.form.get("is_active") or "off")=="on"
        if not name:
            flash("Nom obligatoire.", "error"); return redirect(url_for("admin_formations"))
        other=Formation.query.filter(Formation.name==name, Formation.id!=f.id).first()
        if other:
            flash("Nom déjà utilisé par une autre formation.", "error"); return redirect(url_for("admin_formations"))
        f.name=name; f.formation_text=ft; f.engagement_text=et; f.is_active=is_active
        db.session.commit()
        flash("Formation mise à jour.", "ok")
        return redirect(url_for("admin_formations"))

    @app.post(admin_base + "/formations/delete/<int:formation_id>")
    @login_required(role="root")
    def admin_formations_delete(formation_id:int):
        f=Formation.query.get_or_404(formation_id)
        used=FormationRecord.query.filter_by(formation_id=f.id).first()
        if used:
            f.is_active=False; db.session.commit()
            flash("Formation désactivée (utilisée dans des enregistrements).", "ok")
            return redirect(url_for("admin_formations"))
        db.session.delete(f); db.session.commit()
        flash("Formation supprimée.", "ok")
        return redirect(url_for("admin_formations"))

    # ROOT: admins
    @app.get(admin_base + "/admins")
    @login_required(role="root")
    def admin_admins():
        admins=AdminUser.query.order_by(AdminUser.role.desc(), AdminUser.username.desc()).all()
        return render_template("admin_admins.html", admins=admins, admin=current_admin(), show_admin_nav=True)

    @app.post(admin_base + "/admins/create")
    @login_required(role="root")
    def admin_admins_create():
        username=(request.form.get("username") or "").strip()
        password=(request.form.get("password") or "").strip()
        role=(request.form.get("role") or "admin").strip()
        if role not in ("admin","root"): role="admin"
        if not username or not password:
            flash("Username et mot de passe obligatoires.", "error"); return redirect(url_for("admin_admins"))
        if len(password) < 8:
            flash("Mot de passe min 8 caractères.", "error"); return redirect(url_for("admin_admins"))
        if AdminUser.query.filter_by(username=username).first():
            flash("Username déjà utilisé.", "error"); return redirect(url_for("admin_admins"))
        u=AdminUser(username=username, role=role, is_active=True); u.set_password(password)
        db.session.add(u); db.session.commit()
        flash("Compte admin créé.", "ok")
        return redirect(url_for("admin_admins"))

    @app.post(admin_base + "/admins/update/<int:user_id>")
    @login_required(role="root")
    def admin_admins_update(user_id:int):
        u=AdminUser.query.get_or_404(user_id)
        role=(request.form.get("role") or u.role).strip()
        is_active=(request.form.get("is_active") or "off")=="on"
        new_password=(request.form.get("new_password") or "").strip()
        if u.username == "root":
            role="root"; is_active=True
        if role not in ("admin","root"): role=u.role
        u.role=role; u.is_active=is_active
        if new_password:
            if len(new_password) < 8:
                flash("Nouveau mot de passe min 8 caractères.", "error"); return redirect(url_for("admin_admins"))
            u.set_password(new_password)
        db.session.commit()
        flash("Compte admin mis à jour.", "ok")
        return redirect(url_for("admin_admins"))

    @app.post(admin_base + "/admins/delete/<int:user_id>")
    @login_required(role="root")
    def admin_admins_delete(user_id:int):
        u=AdminUser.query.get_or_404(user_id)
        if u.username == "root":
            flash("Impossible de supprimer le compte root.", "error"); return redirect(url_for("admin_admins"))
        db.session.delete(u); db.session.commit()
        flash("Compte supprimé.", "ok")
        return redirect(url_for("admin_admins"))

    return app

def seed_defaults():
    if AdminUser.query.count() == 0:
        root = AdminUser(username="root", role="root", is_active=True)
        root.set_password("root123")
        db.session.add(root)
    db.session.commit()

if __name__ == "__main__":
    app=create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
