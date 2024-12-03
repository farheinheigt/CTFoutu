#!/usr/bin/env python3

import re
import requests
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from datetime import datetime
import time

# Variables globales
home = str(Path.home())
header = {"User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest"}
console = Console()

def rechercher_cves(arg):
    # Recherche des CVEs correspondant à une chaîne de caractères donnée via l'API NVD
    console.print(f"[bold yellow]Recherche des derniers CVEs liés à '{arg}'[/bold yellow]")
    try:
        url_recherche = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={arg}&resultsPerPage=50"

        for tentative in range(3):  # Essayer 3 fois en cas d'erreur 503
            reponse = requests.get(url_recherche, headers=header)
            if reponse.status_code == 200:
                break
            elif reponse.status_code == 503:
                console.print(f"[bold red]Erreur 503 : Service indisponible. Tentative {tentative + 1} sur 3...[/bold red]")
                time.sleep(5)  # Attendre 5 secondes avant de réessayer
            elif reponse.status_code == 404:
                console.print(f"[bold red]Erreur 404 : Ressource non trouvée. Vérifiez l'URL ou les paramètres de recherche.[/bold red]")
                return
            else:
                console.print(f"[bold red]Erreur : Impossible de récupérer les données (statut {reponse.status_code})[/bold red]")
                return

        if reponse.status_code != 200:
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
        afficher_resultats_recherche(resultats_recherche)
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la recherche des CVEs :[/bold red] {e}")

def afficher_resultats_recherche(resultats):
    # Affiche les résultats de la recherche de CVEs dans un tableau bien formaté
    tableau = Table(title="Résultats de la recherche pour les CVEs")
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

def rechercher_exploits(arg):
    # Recherche des exploits correspondant à une chaîne de caractères donnée dans la base de données locale
    console.print(f"[bold yellow]Recherche des exploits liés à '{arg}'[/bold yellow]")
    try:
        tableau = Table(title=f"Résultats de la recherche pour les exploits : {arg}")
        tableau.add_column("EDB", style="bold red")
        tableau.add_column("Langage", style="bold")
        tableau.add_column("Description", style="yellow")
        tableau.add_column("Auteur", style="cyan")
        tableau.add_column("Date de publication", style="green")
        tableau.add_column("Mise à jour", style="blue")

        correspondances_exploits = list(obtenir_correspondances_exploits(arg))  # Convertir le générateur en liste pour éviter les problèmes de fichier fermé
        # Trier les exploits par date de publication (le plus récent en premier)
        correspondances_exploits = sorted(correspondances_exploits, key=lambda x: x.split(",")[3], reverse=True)
        for exploit in correspondances_exploits:
            details_exploit = exploit.split(",")
            tableau.add_row(f"EDB-{details_exploit[0]}", obtenir_langage_exploit(details_exploit[1]), details_exploit[2][:100].strip('"'), details_exploit[4].strip('"'), details_exploit[3], details_exploit[9])
        console.print(tableau)
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la recherche des exploits :[/bold red] {e}")

def obtenir_correspondances_exploits(arg):
    # Récupère les exploits correspondants à partir du fichier CSV local
    try:
        with open(f"{home}/.local/share/cve-maker/files_exploits.csv", "r") as fichier:
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
    if len(sys.argv) < 2:
        console.print("[bold red]Usage : cve.py <terme-de-recherche>")
        sys.exit(1)
    
    terme_recherche = " ".join(sys.argv[1:])
    rechercher_cves(terme_recherche)
    rechercher_exploits(terme_recherche)
