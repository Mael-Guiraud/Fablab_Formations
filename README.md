# formation_app_v3

## Inclus
- Aucun lien admin sur les pages publiques (formulaire + succès), même si un admin est connecté.
- Admin accessible uniquement via une URL connue (ADMIN_PATH).
- Page "Mot de passe" pour changer le mot de passe de l'admin connecté.
- Gestion des comptes admins (root) : création / activation / rôle / reset password / suppression.
- Formations avec 2 textes : Formation + Engagement.
- PDF : titres "Formation :" et "Engagement :" en bleu.

## Démarrage
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## URL
- Public : http://127.0.0.1:5000/
- Admin : http://127.0.0.1:5000/panel-nrfablab/login

## Compte root initial
- root / root123 (non affiché dans l'UI). Change-le dès la première connexion via "Mot de passe".

## Important (DB)
Si tu avais une DB précédente, supprime `instance/app.db` (schéma différent).
- Linux: `rm -f instance/app.db`
- Windows: `Remove-Item .\instance\app.db`

## Logo CESI
Dépose `static/cesi_logo.png` (PNG) pour l'afficher en haut du PDF.
