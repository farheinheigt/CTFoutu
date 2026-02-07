#!/usr/bin/env python3

import argparse
import csv
import json
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.table import Table
from yaspin import yaspin

from config import charger_configuration, obtenir_ou_configurer_cle_api

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOIT_DB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
REQUEST_TIMEOUT_SECONDS = 20
MAX_RETRIES = 3
BASE_HEADERS = {"User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest"}

CVE_FIELDS = ["CVE", "CVSS", "Fournisseur", "Produit", "Description", "Publication"]
EXPLOIT_FIELDS = ["EDB", "Langage", "Description", "Auteur", "Publication", "Mise a jour"]

console = Console()


def _date_sort_key(date_str: str) -> datetime:
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return datetime.min


def _extract_cvss_score(metrics: dict[str, Any]) -> str:
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_entries = metrics.get(metric_key, [])
        if not metric_entries:
            continue
        cvss_data = metric_entries[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is not None:
            return str(score)
    return "N/A"


def _nvd_request(keyword: str, headers: dict[str, str]) -> requests.Response | None:
    params = {"keywordSearch": keyword, "resultsPerPage": 50}

    for tentative in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                NVD_ENDPOINT,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            console.print(
                f"[bold red]Erreur reseau NVD (tentative {tentative}/{MAX_RETRIES}) :[/bold red] {exc}"
            )
            if tentative < MAX_RETRIES:
                time.sleep(2)
                continue
            return None

        if response.status_code == 200:
            return response
        if response.status_code == 404 and headers.get("apiKey"):
            console.print(
                "[bold yellow]NVD a retourne HTTP 404 avec cle API. "
                "Ce statut indique souvent une cle invalide/expiree.[/bold yellow]"
            )
            console.print(
                "[bold yellow]Verification conseillee: la variable NVD_API_KEY prioritaire "
                "peut ecraser la cle configuree via --conf.[/bold yellow]"
            )
            fallback_headers = dict(headers)
            fallback_headers.pop("apiKey", None)
            try:
                fallback = requests.get(
                    NVD_ENDPOINT,
                    headers=fallback_headers,
                    params=params,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
            except requests.RequestException:
                fallback = None
            if fallback is not None and fallback.status_code == 200:
                console.print(
                    "[bold yellow]Poursuite en mode sans cle API (rate limit plus faible).[/bold yellow]"
                )
                return fallback
        if response.status_code == 503 and tentative < MAX_RETRIES:
            console.print(
                f"[bold red]Erreur 503 NVD, nouvelle tentative {tentative + 1}/{MAX_RETRIES} dans 5s...[/bold red]"
            )
            time.sleep(5)
            continue

        console.print(
            f"[bold red]Erreur NVD : statut HTTP {response.status_code}. Verifie la cle API et la requete.[/bold red]"
        )
        return None

    return None


def _parse_cve_results(payload: dict[str, Any]) -> list[tuple[str, str, str, str, str, str]]:
    resultats: list[tuple[str, str, str, str, str, str]] = []

    for item in payload.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "N/A")
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        score = _extract_cvss_score(cve_data.get("metrics", {}))
        publication = cve_data.get("published", "")[:10] or "N/A"
        resultats.append((cve_id, score, "N/A", "N/A", description, publication))

    resultats.sort(key=lambda row: _date_sort_key(row[5]), reverse=True)
    return resultats


def _download_exploit_csv(destination: Path) -> bool:
    try:
        response = requests.get(EXPLOIT_DB_CSV_URL, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        console.print(f"[bold red]Erreur reseau ExploitDB :[/bold red] {exc}")
        return False

    if response.status_code != 200:
        console.print(
            f"[bold red]Erreur : impossible de telecharger la base ExploitDB (HTTP {response.status_code}).[/bold red]"
        )
        return False

    destination.write_bytes(response.content)
    return True


def _langage_depuis_chemin(path: str) -> str:
    extensions = {
        ".cpp": "c++",
        ".c": "c",
        ".sh": "sh",
        ".rb": "ruby",
        ".pl": "perl",
        ".py": "python",
        ".php": "php",
        ".txt": "texte",
        ".jsp": "jsp",
        ".go": "go",
        ".js": "javascript",
    }
    for ext, lang in extensions.items():
        if path.endswith(ext):
            return lang
    return "inconnu"


def _search_exploits(keyword: str, csv_file: Path) -> list[tuple[str, str, str, str, str, str]]:
    mot_cle = keyword.casefold()
    resultats: list[tuple[str, str, str, str, str, str]] = []

    try:
        with csv_file.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                haystack = " ".join(
                    [
                        row.get("description", ""),
                        row.get("file", ""),
                        row.get("codes", ""),
                        row.get("tags", ""),
                        row.get("aliases", ""),
                    ]
                ).casefold()
                if mot_cle not in haystack:
                    continue

                resultats.append(
                    (
                        row.get("id", "N/A"),
                        _langage_depuis_chemin(row.get("file", "")),
                        row.get("description", "").strip()[:100],
                        row.get("author", "N/A").strip(),
                        row.get("date_published", "N/A").strip(),
                        row.get("date_updated", "N/A").strip(),
                    )
                )
    except OSError as exc:
        console.print(f"[bold red]Erreur de lecture du CSV ExploitDB :[/bold red] {exc}")
        return []

    resultats.sort(key=lambda row: _date_sort_key(row[4]), reverse=True)
    return resultats


def _header_for_title(titre: str) -> list[str]:
    return CVE_FIELDS if titre == "CVEs" else EXPLOIT_FIELDS


def _resultats_en_dicts(resultats: list[tuple[str, ...]], titre: str) -> list[dict[str, str]]:
    headers = _header_for_title(titre)
    return [dict(zip(headers, resultat)) for resultat in resultats]


def obtenir_couleur_cvss(score: str) -> str:
    try:
        valeur = float(score)
    except ValueError:
        return "[white]N/A[/white]"

    if valeur > 8.9:
        return f"[bold red]{score}[/bold red]"
    if valeur > 6.9:
        return f"[bold yellow]{score}[/bold yellow]"
    if valeur > 3.9:
        return f"[bold blue]{score}[/bold blue]"
    return f"[bold green]{score}[/bold green]"


def afficher_resultats_recherche(resultats: list[tuple[str, ...]], titre: str) -> None:
    tableau = Table(title=f"Resultats de la recherche pour les {titre}")

    if titre == "CVEs":
        tableau.add_column("CVE", style="bold red")
        tableau.add_column("CVSS", style="bold")
        tableau.add_column("Fournisseur", style="cyan")
        tableau.add_column("Produit", style="magenta")
        tableau.add_column("Description", style="yellow")
        tableau.add_column("Publication", style="green")

        for resultat in resultats:
            score_couleur = obtenir_couleur_cvss(resultat[1] or "N/A")
            tableau.add_row(
                resultat[0],
                score_couleur,
                resultat[2].upper()[:20],
                resultat[3][:20],
                resultat[4][:100],
                resultat[5],
            )
    else:
        tableau.add_column("EDB", style="bold red")
        tableau.add_column("Langage", style="cyan")
        tableau.add_column("Description", style="yellow")
        tableau.add_column("Auteur", style="magenta")
        tableau.add_column("Publication", style="green")
        tableau.add_column("Mise a jour", style="green")

        for resultat in resultats:
            tableau.add_row(
                resultat[0],
                f"[cyan]{resultat[1]}[/cyan]",
                resultat[2][:100],
                resultat[3][:35],
                resultat[4],
                resultat[5],
            )

    console.print(tableau)


def sauvegarder_resultats(resultats: list[tuple[str, ...]], titre: str) -> None:
    nom_fichier_md = f"resultats_{titre.lower()}.md"
    nom_fichier_json = f"resultats_{titre.lower()}.json"
    headers = _header_for_title(titre)

    try:
        with open(nom_fichier_md, "w", encoding="utf-8") as fichier_md:
            fichier_md.write(f"# Resultats de la recherche pour les {titre}\n\n")
            fichier_md.write("| " + " | ".join(headers) + " |\n")
            fichier_md.write("|" + "|".join(["---"] * len(headers)) + "|\n")
            for resultat in resultats:
                fichier_md.write("| " + " | ".join(resultat) + " |\n")
        console.print(f"[bold green]Resultats sauvegardes en Markdown : {nom_fichier_md}[/bold green]")

        resultats_json = _resultats_en_dicts(resultats, titre)
        with open(nom_fichier_json, "w", encoding="utf-8") as fichier_json:
            json.dump(resultats_json, fichier_json, indent=4, ensure_ascii=False)
        console.print(f"[bold green]Resultats sauvegardes en JSON : {nom_fichier_json}[/bold green]")
    except OSError as exc:
        console.print(f"[bold red]Erreur lors de la sauvegarde des resultats :[/bold red] {exc}")


def rechercher_cves_et_exploits(terme: str, headers: dict[str, str]) -> None:
    console.print(f"[bold yellow]Recherche des derniers CVEs lies a '{terme}'[/bold yellow]")
    with yaspin(text="Recherche des CVEs...", color="yellow") as spinner:
        response = _nvd_request(terme, headers)
        if response is None:
            spinner.fail("✖")
            return
        spinner.ok("✔")

    try:
        cves = _parse_cve_results(response.json())
    except ValueError as exc:
        console.print(f"[bold red]Reponse JSON NVD invalide :[/bold red] {exc}")
        return

    if cves:
        afficher_resultats_recherche(cves, "CVEs")
        sauvegarder_resultats(cves, "CVEs")
    else:
        console.print("[bold yellow]Aucun CVE trouve pour ce terme.[/bold yellow]")

    console.print(f"[bold yellow]Recherche des exploits lies a '{terme}'[/bold yellow]")
    with tempfile.NamedTemporaryFile(prefix="ctfoutu_", suffix=".csv", delete=False) as tmp:
        fichier_temp = Path(tmp.name)

    try:
        with yaspin(text="Recherche des exploits...", color="cyan") as spinner:
            if not _download_exploit_csv(fichier_temp):
                spinner.fail("✖")
                return
            exploits = _search_exploits(terme, fichier_temp)
            spinner.ok("✔")
    finally:
        fichier_temp.unlink(missing_ok=True)

    if exploits:
        afficher_resultats_recherche(exploits, "Exploits")
        sauvegarder_resultats(exploits, "Exploits")
    else:
        console.print("[bold yellow]Aucun exploit trouve pour ce terme.[/bold yellow]")


def _build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="CTFoutu - Outil de recherche de CVEs et d'exploits associes.",
        epilog="""
Exemples d'utilisation :
  - Rechercher des CVEs : ctfoutu "apache"
  - Configurer la cle API : ctfoutu --conf
  - Utiliser un pipe : echo "apache" | ctfoutu
        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    parser.add_argument("terme_recherche", nargs="?")
    parser.add_argument(
        "--conf",
        action="store_true",
        help="Configurer la cle API pour l'acces NVD",
    )
    args = parser.parse_args(argv)

    if args.conf:
        api_key = obtenir_ou_configurer_cle_api()
        if api_key and api_key.strip():
            console.print("[bold green]Cle API configuree avec succes.[/bold green]")
            return 0
        console.print("[bold red]Aucune cle API configuree.[/bold red]")
        return 1

    config = charger_configuration()
    api_key = os.getenv("NVD_API_KEY", "").strip() or config.get("api_key", "").strip()
    if not api_key:
        console.print(
            "[bold red]Erreur : aucune cle API configuree. Utilise '--conf' ou la variable NVD_API_KEY.[/bold red]"
        )
        return 1

    headers = dict(BASE_HEADERS)
    headers["apiKey"] = api_key

    if args.terme_recherche:
        terme_recherche = args.terme_recherche.strip()
    elif not sys.stdin.isatty():
        terme_recherche = sys.stdin.read().strip()
    else:
        terme_recherche = ""

    if not terme_recherche:
        parser.print_help()
        return 1

    rechercher_cves_et_exploits(terme_recherche, headers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
