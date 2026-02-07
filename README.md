# CTFoutu

CTFoutu est un CLI pour rechercher rapidement des CVEs (NVD) et des exploits associés (ExploitDB).

<img src="demo.gif" alt="Démo de CTFoutu" />

## Fonctionnalités

- Recherche de CVEs via l'API officielle NVD.
- Affichage des scores CVSS avec couleur selon la sévérité.
- Recherche d'exploits depuis la base ExploitDB (`files_exploits.csv`).
- Entrée via argument ou via pipe.
- Export des résultats en Markdown et JSON.

## Prérequis

- Python 3.10+
- `uv` installé: <https://docs.astral.sh/uv/>

### Prérequis shell (XDG / PATH)

Pas obligatoire, mais recommandé pour un setup propre.

- `uv` place les exécutables dans le dossier `XDG_BIN_HOME` si défini.
- Sinon, `uv` utilise un dossier par défaut (souvent `~/bin`).

Exemple recommandé:

```bash
export XDG_LOCAL_HOME="$HOME/.local"
export XDG_BIN_HOME="$XDG_LOCAL_HOME/bin"
export PATH="$XDG_BIN_HOME:$PATH"
```

Puis recharge ton shell (`exec zsh`).

## Installation

### Option A: exécution dans le projet (`uv run`)

```bash
git clone https://github.com/farheinheigt/CTFoutu.git
cd CTFoutu
uv sync
```

Exécuter le CLI dans l'environnement du projet:

```bash
uv run ctfoutu --help
```

### Option B: installation globale (sans alias)

Depuis le dossier du projet:

```bash
uv tool install .
ctfoutu --help
```

Si `ctfoutu` est introuvable après installation, vérifie ton `PATH`:

```bash
uv tool dir --bin
```

Ajoute ce dossier au `PATH` si nécessaire.

## Désinstallation

### Si tu utilises seulement le mode projet (`uv run`)

Depuis le dossier du projet:

```bash
rm -rf .venv
```

Puis supprime le dossier du repo si tu n'en as plus besoin.

### Si tu as installé l'outil globalement (`uv tool install .`)

```bash
uv tool uninstall ctfoutu
```

Optionnel: supprimer la configuration locale et les résultats exportés.

```bash
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/ctfoutu/config.json"
rm -f resultats_cves.md resultats_cves.json resultats_exploits.md resultats_exploits.json
```

## Configuration de la clé API NVD

CTFoutu nécessite une clé API NVD.

Option 1 (recommandée): variable d'environnement.

```bash
export NVD_API_KEY="ta_cle_api"
uv run ctfoutu "apache"
```

La variable `NVD_API_KEY` est prioritaire sur la clé stockée en local.

Option 2: configuration interactive.

```bash
uv run ctfoutu --conf
```

Emplacement du fichier de config local:

- macOS/Linux: `${XDG_CONFIG_HOME:-~/.config}/ctfoutu/config.json`
- Windows: `%APPDATA%\\ctfoutu\\config.json`

Surcharge possible via `CTFOUTU_CONFIG`.

Exemple de config locale:

```json
{
  "api_key": "NVD_API_KEY_HERE"
}
```

## Utilisation

Recherche classique:

```bash
uv run ctfoutu "apache"
```

Si tu as installé l'outil globalement:

```bash
ctfoutu "apache"
```

Recherche via pipe:

```bash
echo "apache" | uv run ctfoutu
```

## Fichiers générés

Dans le dossier courant:

- `resultats_cves.md`
- `resultats_cves.json`
- `resultats_exploits.md`
- `resultats_exploits.json`

## Développement

Synchroniser les dépendances:

```bash
uv sync
```

Lancer le script directement (équivalent au binaire):

```bash
uv run python ctfoutu.py --help
```

## Notes de migration

Le projet n'utilise plus `pipenv`/`requirements.txt`.
Le mode de gestion de dépendances est désormais standardisé sur `uv` + `pyproject.toml`.

## Dépannage

### Erreur NVD HTTP 404

Sur l'API NVD, un `HTTP 404` peut indiquer une clé API invalide/expirée.

- Vérifie d'abord si `NVD_API_KEY` est défini dans ton shell (elle écrase la clé locale).
- Reconfigure la clé via `ctfoutu --conf` si besoin.

Vérification directe:

```bash
curl -i -H "apiKey: TA_CLE" "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx&resultsPerPage=1"
```

- `200` : clé valide.
- `404` : clé invalide ou rejetée.

## Licence

MIT
