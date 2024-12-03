# CTFoutu

## Description

CTFoutu est un outil de recherche des vulnérabilités (CVE) et des exploits associés. Cet outil permet de rechercher facilement les CVEs à partir de la base de données officielle du NVD (National Vulnerability Database) et d'afficher les exploits correspondants présents dans une base de données locale.

## Prérequis

- Python 3
- Bibliothèques Python : `requests`, `rich`

Pour installer ces bibliothèques, vous pouvez exécuter la commande suivante :

```bash
pip install requests rich
```

## Installation

1. Clonez ce dépôt sur votre machine :
   ```bash
   git clone <url-du-repo>
   ```
2. Accédez au répertoire du projet :
   ```bash
   cd CTFoutu
   ```

## Utilisation

Pour utiliser CTFoutu, exécutez le script avec un terme de recherche en argument. Ce terme peut être un mot-clé comme le nom d'un produit ou d'une technologie.

```bash
./ctfoutu.py "apache"
```

L'outil affichera alors les CVEs et les exploits liés à "apache".

### Exemple de sortie

L'outil affichera deux tableaux :

1. **Tableau des CVEs** :

   - **CVE** : Identifiant du CVE
   - **CVSS** : Score de gravité CVSS
   - **Fournisseur** : Nom du fournisseur (si disponible)
   - **Produit** : Nom du produit (si disponible)
   - **Description** : Brève description du CVE
   - **Mise à jour** : Date de publication

2. **Tableau des exploits** :

   - **EDB** : Identifiant de l'exploit dans la base ExploitDB
   - **Langage** : Langage de programmation de l'exploit
   - **Description** : Description courte de l'exploit
   - **Auteur** : Auteur de l'exploit
   - **Date de publication** : Date à laquelle l'exploit a été publié
   - **Mise à jour** : Date de la dernière mise à jour de l'exploit

## Fonctionnalités

- Recherche des CVEs via l'API de la NVD.
- Affichage des scores CVSS avec une mise en évidence en couleur en fonction de la gravité.
- Recherche des exploits à partir d'une base de données locale (fichier `files_exploits.csv`).

## Remarque

- Assurez-vous que le fichier `files_exploits.csv` est correctement téléchargé et placé dans le répertoire `~/.local/share/CTFoutu/` afin de permettre la recherche des exploits.
- Vous pouvez configurer la durée de pause pour les tentatives en cas d'erreur de connexion dans le code (par défaut 5 secondes).

## Structure du Projet

- **ctfoutu.py** : Le script principal permettant de faire les recherches.
- **files\_exploits.csv** : Fichier contenant la base de données des exploits utilisée pour la recherche.

## Contributions

Les contributions sont les bienvenues. N'hésitez pas à proposer des correctifs ou de nouvelles fonctionnalités via des pull requests.

## Licence

Ce projet est distribué sous licence MIT. Consultez le fichier `LICENSE` pour plus de détails.

## Aide et Support

Si vous rencontrez des problèmes ou avez des questions concernant l'utilisation de cet outil, vous pouvez ouvrir une *issue* sur le dépôt GitHub.

