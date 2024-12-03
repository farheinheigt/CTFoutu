import json
import os
import webbrowser
from cryptography.fernet import Fernet
from rich.console import Console

CONFIG_FILE = "config.json"
console = Console()

def charger_configuration():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            return config
    return {}

def sauvegarder_configuration(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

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
    # Ouvrir la page pour générer une clé API
    webbrowser.open("https://nvd.nist.gov/developers/request-an-api-key")
    
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
