import json
import os
import webbrowser
from pathlib import Path
from rich.console import Console

console = Console()

def _chemin_config() -> Path:
    override = os.getenv("CTFOUTU_CONFIG")
    if override:
        return Path(override).expanduser()

    if os.name == "nt":
        base = Path(os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    else:
        base = Path(os.getenv("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    return base / "ctfoutu" / "config.json"


CONFIG_FILE = _chemin_config()


def charger_configuration():
    if CONFIG_FILE.exists():
        try:
            with CONFIG_FILE.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            console.print(f"[bold red]Impossible de lire la configuration :[/bold red] {exc}")
    return {}


def sauvegarder_configuration(config):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=4, ensure_ascii=False)


def obtenir_ou_configurer_cle_api():
    config = charger_configuration()

    # Vérifier si la clé API est déjà configurée et n'est pas vide
    if "api_key" in config and config["api_key"]:
        api_key = config["api_key"].strip()
        if api_key:
            console.print("[bold orange]Une clé API est déjà configurée.[/bold orange]")
            choix = console.input("[bold green]Souhaites-tu la mettre à jour ? (oui/non) : [/bold green]").strip().lower()
            if choix != "oui":
                return api_key

    # Lancer directement le processus de configuration sans redemander
    console.print("[bold cyan]Je vais ouvrir la page pour générer une clé API dans ton navigateur...[/bold cyan]")
    url_api = "https://nvd.nist.gov/developers/request-an-api-key"
    try:
        webbrowser.open(url_api)
    except webbrowser.Error:
        console.print(f"[bold yellow]Ouvre ce lien manuellement : {url_api}[/bold yellow]")
    
    api_key = console.input("[bold green]Entre ta clé API ici : [/bold green]").strip()

    if api_key:
        # Sauvegarder la configuration
        config["api_key"] = api_key
        sauvegarder_configuration(config)
        return api_key
    else:
        console.print("[bold red]Aucune clé API n'a été fournie. Configuration annulée.[/bold red]")
        return None

if __name__ == '__main__':
    # Cette partie sera exécutée par ctfoutu.py
    pass
