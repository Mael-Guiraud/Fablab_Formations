from __future__ import annotations
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
def utcnow(): return datetime.now(timezone.utc)

class AdminUser(db.Model):
    __tablename__ = "admin_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="admin")  # root/admin
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    def set_password(self, pwd:str)->None: self.password_hash = generate_password_hash(pwd)
    def check_password(self, pwd:str)->bool: return check_password_hash(self.password_hash, pwd)

class Trainer(db.Model):
    __tablename__ = "trainers"
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (db.UniqueConstraint("last_name","first_name", name="uq_trainer_last_first"),)
    def display_name(self)->str: return f"{self.first_name} {self.last_name}".strip()

class Formation(db.Model):
    __tablename__ = "formations"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    formation_text = db.Column(db.Text, nullable=False, default="")
    engagement_text = db.Column(db.Text, nullable=False, default="")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

class FormationRecord(db.Model):
    __tablename__ = "formation_records"
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(120), nullable=False)
    prenom = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    trainer_id = db.Column(db.Integer, db.ForeignKey("trainers.id"), nullable=False)
    formation_id = db.Column(db.Integer, db.ForeignKey("formations.id"), nullable=False)
    date_formation = db.Column(db.Date, nullable=False)
    signature_forme_path = db.Column(db.String(512), nullable=False)
    signature_formateur_path = db.Column(db.String(512), nullable=False)
    attestation_pdf_path = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    trainer = db.relationship("Trainer")
    formation = db.relationship("Formation")
    def full_name(self)->str: return f"{self.prenom} {self.nom}"
