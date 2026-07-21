# DarkBox

DarkBox ist ein kleines, dunkles File-Upload-Projekt inspiriert von catbox.moe. Es ist nicht 1:1 kopiert — stattdessen eine eigene, dunkle Variante mit Upload-API und SQLite-DB.

Voraussetzungen:
- Node.js (>=14)

Installation & Start:

```bash
npm install
npm start
```

Die Seite läuft dann auf `http://localhost:3000`.

Dateien werden in `uploads/` gespeichert, Metadaten in `data.sqlite`.

GitHub:
1. Erstelle ein neues Repo.
2. `git init && git add . && git commit -m "initial" && git remote add origin <URL> && git push -u origin main`

Hinweis: Wenn du das Projekt öffentlich auf GitHub hochlädst, enthält das Repo keine hochgeladenen Dateien (der Ordner `uploads/` sollte in `.gitignore` stehen, füge ihn hinzu, falls gewünscht).

Upload auf GitHub (einfach):

Wenn du das Projekt in ein neues GitHub-Repo hochladen willst, kannst du folgende Schritte nutzen.

1) Mit klassischem Git (ersetze `<URL>` durch die Remote-URL):

```bash
git init
git add .
git commit -m "initial"
git remote add origin <URL>
git branch -M main
git push -u origin main
```

2) Oder mit der GitHub CLI (`gh`) automatisch (ersetze `<name>`):

```bash
gh repo create <name> --public --source=. --remote=origin --push
```

Es gibt ein Hilfs-Skript `publish.bat`, das das lokale Repo initialisiert und Hinweise zum Pushen ausgibt. Verwende es nur, wenn du lokale Commits automatisch erstellen möchtest.

GitHub Pages (Frontend automatisch deployen)
-----------------------------------------

Das Frontend in `public/` kann automatisch zu GitHub Pages deployed werden, sodass du eine Domain (z.B. `https://username.github.io/repo` oder eine eigene Domain) direkt verwendest.

1) Stelle sicher, dass dein Haupt-Branch `main` heißt und pushe zu GitHub.
2) Die Action `.github/workflows/pages.yml` ist im Repo und deployed den Inhalt von `public/` bei jedem Push auf `main`.
3) Um eine eigene Domain zu verwenden, ersetze den Inhalt von `public/CNAME` mit deiner Domain und konfiguriere die DNS-Einträge bei deinem Registrar (A/ALIAS/ANAME oder CNAME gemäß GitHub Pages Anleitung).

Wichtig: GitHub Pages hostet nur das statische Frontend. Unsere API/Backend (`server.js`) benötigt einen Node-Server — du musst diesen separat hosten (z.B. Render, Railway, Heroku, ein VPS oder als Container). Unten stehen zwei einfache Optionen.

Backend-Deployment (kurzanleitung)
--------------------------------

Option A — Render (einfach):
- Erstelle ein neues Web Service bei Render und verbinde dein GitHub-Repo.
- Setze den Startbefehl auf `node server.js` und Umgebungsvariablen falls nötig.
- Render bietet ein Dashboard zum Zuweisen einer Domain (oder Verwende Render-Subdomain).

Option B — Railway/Heroku: Verbinde dein Repo und setze den Startbefehl `node server.js`. Beide Plattformen bieten freie/kleine Pläne.

Option C — Container-Host oder VPS:
- Baue das Docker-Image mit dem beiliegenden `Dockerfile` und deploye es zu deiner Plattform. Beispiel lokal:

```bash
docker build -t darkbox:latest .
docker run -p 3000:3000 darkbox:latest
```

Domain verbinden
-----------------
- Wenn du Frontend und Backend getrennt hostest: Richte DNS-Einträge so, dass deine Domain auf den statischen Host (GitHub Pages oder Render Pages) oder auf den Backend-Host zeigt. Bei GitHub Pages musst du in den Repository-Einstellungen unter Pages die benutzerdefinierte Domain setzen.
- Wenn du das gesamte Node-Server-Setup hostest (z.B. Render oder VPS), kannst du die Domain direkt auf diesen Host zeigen.

Automatisierung (optional)
--------------------------
- Die Action `pages.yml` deployed das Frontend automatisch.
- Für automatisches Backend-Deployment braucht es Plattform-spezifische Schritte (z.B. Render GitHub Link, oder GitHub Actions mit Secrets für Heroku/Render API). Ich kann bei Bedarf eine Action-Datei hinzufügen, sofern du mir sagst, welchen Dienst du verwenden möchtest und ob du Repo-Secrets (API-Tokens) setzen kannst.
