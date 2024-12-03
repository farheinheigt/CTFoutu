#!/usr/bin/env python3

import re
import requests
import sys
import time
import os
import json
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table
from datetime import datetime
from yaspin import yaspin
from config import obtenir_ou_configurer_cle_api, charger_configuration

# Variables globales
header = {"User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest"}
console = Console()

def rechercher_cves_et_exploits(arg):
    # Recherche des CVEs correspondant à une chaîne de caractères donnée via l'API NVD
    console.print(f"[bold yellow]Recherche des derniers CVEs liés à '{arg}'[/bold yellow]")
    try:
        url_recherche = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={arg}&resultsPerPage=50"

        with yaspin(text="Recherche des CVEs...", color="yellow") as spinner:
            for tentative in range(3):  # Essayer 3 fois en cas d'erreur 503
                reponse = requests.get(url_recherche, headers=header)
                if reponse.status_code == 200:
                    spinner.ok("✔")
                    break
                elif reponse.status_code == 503:
                    console.print(f"[bold red]Erreur 503 : Service indisponible. Tentative {tentative + 1} sur 3...[/bold red]")
                    time.sleep(5)  # Attendre 5 secondes avant de réessayer
                elif reponse.status_code == 404:
                    spinner.fail("✖")
                    console.print(f"[bold red]Erreur 404 : Ressource non trouvée. Vérifiez l'URL ou les paramètres de recherche.[/bold red]")
                    return
                else:
                    spinner.fail("✖")
                    console.print(f"[bold red]Erreur : Impossible de récupérer les données (statut {reponse.status_code})[/bold red]")
                    return

            if reponse.status_code != 200:
                spinner.fail("✖")
                console.print(f"[bold red]Erreur : Impossible de récupérer les données après plusieurs tentatives[/bold red]")
                return

        donnees = reponse.json()
        resultats_recherche = []

        for cve in donnees.get("vulnerabilities", []):
            cve_data = cve.get("cve", {})
            cve_id = cve_data.get("id", "")
            description = cve_data.get("descriptions", [{}])[0].get("value", "")
            score = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            date_publication = cve_data.get("published", "")[:10]
            resultats_recherche.append((cve_id, score, "N/A", "N/A", description, date_publication))

        # Trier les résultats par date de publication (le plus récent en premier)
        resultats_recherche = sorted(resultats_recherche, key=lambda x: datetime.strptime(x[5], "%Y-%m-%d"), reverse=True)
        afficher_resultats_recherche(resultats_recherche, "CVEs")
        sauvegarder_resultats(resultats_recherche, "CVEs")
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la recherche des CVEs :[/bold red] {e}")

    # Recherche des exploits correspondant à une chaîne de caractères donnée dans la base de données locale
    console.print(f"[bold yellow]Recherche des exploits liés à '{arg}'[/bold yellow]")
    fichier_exploits = "./files_exploits.csv"
    try:
        with yaspin(text="Recherche des exploits...", color="cyan") as spinner:
            # Télécharger le fichier exploits si nécessaire
            if not os.path.exists(fichier_exploits):
                url_exploits = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
                reponse_exploits = requests.get(url_exploits)
                if reponse_exploits.status_code == 200:
                    with open(fichier_exploits, "wb") as f:
                        f.write(reponse_exploits.content)
                else:
                    spinner.fail("✖")
                    console.print(f"[bold red]Erreur : Impossible de télécharger le fichier des exploits (statut {reponse_exploits.status_code})[/bold red]")
                    return

            correspondances_exploits = list(obtenir_correspondances_exploits(arg, fichier_exploits))  # Convertir le générateur en liste pour éviter les problèmes de fichier fermé
            # Trier les exploits par date de publication (le plus récent en premier)
            correspondances_exploits = sorted(correspondances_exploits, key=lambda x: x.split(",")[3], reverse=True)
            resultats_exploits = []
            for exploit in correspondances_exploits:
                details_exploit = exploit.split(",")
                resultats_exploits.append((details_exploit[0], obtenir_langage_exploit(details_exploit[1]), details_exploit[2][:100].strip('"'), details_exploit[4].strip('"'), details_exploit[3], details_exploit[9]))
            spinner.ok("✔")
        afficher_resultats_recherche(resultats_exploits, "Exploits")
        sauvegarder_resultats(resultats_exploits, "Exploits")
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la recherche des exploits :[/bold red] {e}")
    finally:
        # Supprimer le fichier local après utilisation
        if os.path.exists(fichier_exploits):
            os.remove(fichier_exploits)

def afficher_resultats_recherche(resultats, titre):
    # Affiche les résultats de la recherche dans un tableau bien formaté
    tableau = Table(title=f"Résultats de la recherche pour les {titre}")
    tableau.add_column("CVE", style="bold red")
    tableau.add_column("CVSS", style="bold")
    tableau.add_column("Fournisseur", style="cyan")
    tableau.add_column("Produit", style="magenta")
    tableau.add_column("Description", style="yellow")
    tableau.add_column("Mise à jour", style="green")
    
    for resultat in resultats:
        score = resultat[1] if resultat[1] else "N/A"
        score_couleur = obtenir_couleur_cvss(score)
        tableau.add_row(resultat[0], score_couleur, resultat[2].upper()[:20], resultat[3][:20], resultat[4][:100], resultat[5])
    console.print(tableau)

def sauvegarder_resultats(resultats, titre):
    # Sauvegarder les résultats de la recherche au format Markdown et JSON
    nom_fichier_md = f"resultats_{titre.lower()}.md"
    nom_fichier_json = f"resultats_{titre.lower()}.json"
    
    try:
        # Sauvegarder en Markdown
        with open(nom_fichier_md, "w") as fichier_md:
            fichier_md.write(f"# Résultats de la recherche pour les {titre}\n\n")
            fichier_md.write("| CVE/EDB | CVSS/Langage | Fournisseur | Produit | Description | Mise à jour |\n")
            fichier_md.write("|----------|-------------|------------|---------|-------------|-------------|\n")
            for resultat in resultats:
                ligne = f"| {resultat[0]} | {resultat[1]} | {resultat[2]} | {resultat[3]} | {resultat[4]} | {resultat[5]} |\n"
                fichier_md.write(ligne)
        console.print(f"[bold green]Résultats sauvegardés en Markdown : {nom_fichier_md}[/bold green]")
        
        # Sauvegarder en JSON
        with open(nom_fichier_json, "w") as fichier_json:
            json.dump(resultats, fichier_json, indent=4)
        console.print(f"[bold green]Résultats sauvegardés en JSON : {nom_fichier_json}[/bold green]")
    except IOError as e:
        console.print(f"[bold red]Erreur lors de la sauvegarde des résultats :[/bold red] {e}")

def obtenir_couleur_cvss(score):
    # Détermine la couleur à afficher en fonction du score CVSS
    try:
        valeur_score = float(score)
        if valeur_score > 8.9:
            return f"[bold red]{score}[/bold red]"
        elif valeur_score > 6.9:
            return f"[bold yellow]{score}[/bold yellow]"
        elif valeur_score > 3.9:
            return f"[bold blue]{score}[/bold blue]"
        else:
            return f"[bold green]{score}[/bold green]"
    except ValueError:
        return "[white]N/A[/white]"

def obtenir_correspondances_exploits(arg, fichier_exploits):
    # Récupère les exploits correspondants à partir du fichier CSV local
    try:
        with open(fichier_exploits, "r") as fichier:
            return [ligne for ligne in fichier if arg.casefold() in ligne.casefold()]
    except IOError as e:
        console.print(f"[bold red]Erreur de lecture/écriture du fichier :[/bold red] {e}")
        return []

def obtenir_langage_exploit(chemin):
    # Détermine le langage de programmation de l'exploit en fonction de son extension de fichier
    extensions = {
        ".cpp": "c++",
        ".c": "c",
        ".sh": "sh",
        ".rb": "ruby",
        ".pl": "perl",
        ".py": "python",
        ".php": "php",
        ".txt": "texte",
        ".jsp": "jsp"
    }
    for ext, lang in extensions.items():
        if chemin.endswith(ext):
            return f"[cyan]{lang}[/cyan]"
    return "[white]inconnu[/white]"

if __name__ == '__main__':
    import argparse

    # Utiliser argparse pour analyser les arguments de ligne de commande
    parser = argparse.ArgumentParser(
        description="CTFoutu - Un outil pour rechercher des CVEs et des exploits.",
        epilog="""
Exemples d'utilisation :
  - Pour rechercher des vulnérabilités CVE : ./ctfoutu.py "apache"
  - Pour configurer la clé API : ./ctfoutu.py --conf
  - Pour rechercher des vulnérabilités avec un pipe : echo "apache" | ./ctfoutu.py
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'terme_recherche',
        nargs='?',
        help=argparse.SUPPRESS  # Suppression de la description, l'exemple dans epilog est suffisant
    )
    parser.add_argument(
        '--conf',
        action='store_true',
        help="Configurer la clé API pour accéder aux informations du NVD"
    )
    args = parser.parse_args()

    # Si aucun argument n'est fourni, afficher l'aide
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Charger la clé API via la configuration ou demander une nouvelle configuration
    if args.conf:
        # Si l'option --conf est présente, on configure la clé API via un prompt
        api_key = obtenir_ou_configurer_cle_api()

        # Vérifier si une clé API a été correctement saisie
        if api_key and api_key.strip() != "":
            console.print("[bold green]Clé API configurée avec succès ![/bold green]")
        else:
            console.print("[bold red]Aucune clé API n'a été configurée. Relance la commande pour essayer à nouveau.[/bold red]")
        sys.exit(0)  # Quitter après la configuration, succès ou échec

    # Charger la configuration existante pour la recherche
    config = charger_configuration()
    api_key = config.get("api_key")
    if api_key and api_key.strip():
        header["apiKey"] = api_key
    elif not api_key:
        console.print("[bold red]Erreur : Aucune clé API configurée. Veuillez configurer une clé API avec l'option '--conf'.[/bold red]")
        sys.exit(1)

    # Vérifie si une entrée est fournie via un argument ou via un pipe
    if not sys.stdin.isatty():
        # Lecture de l'entrée du pipe
        terme_recherche = sys.stdin.read().strip()
    elif args.terme_recherche:
        # Lecture de l'argument de ligne de commande
        terme_recherche = args.terme_recherche
    else:
        parser.print_help()
        sys.exit(1)

    # Lancer la recherche avec le terme donné
    rechercher_cves_et_exploits(terme_recherche)
