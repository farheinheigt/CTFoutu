# CTFoutu

## Description

CTFoutu est un outil de recherche des vulnérabilités (CVE) et des exploits associés. Cet outil permet de rechercher facilement les CVEs à partir de la base de données officielle du NVD (National Vulnerability Database) et d'afficher les exploits correspondants présents dans une base de données locale.

<img src="demo.gif" width="1920" height="1080" alt="Démo de CTFoutu" />

## Fonctionnalités

- Recherche des CVEs via l'API de la NVD.
- Affichage des scores CVSS avec une mise en évidence en couleur en fonction de la gravité.
- Recherche des exploits à partir d'une base de données locale (fichier `files_exploits.csv`, provenant de [ExploitDB sur GitLab](https://gitlab.com/exploit-database/exploitdb)).
- Prise en charge de l'entrée via un argument ou un pipe pour une utilisation flexible.
- Sauvegarde des résultats de recherche au format Markdown et JSON dans le répertoire courant.

## Installation

### Prérequis

- Python 3.13 ou supérieur
- Bibliothèques Python : `requests`, `rich`
  
1. Clone ce dépôt sur ta machine :
   ```bash
   git clone https://github.com/farheinheigt/CTFoutu.git
   ```
2. Accède au répertoire du projet :
   ```bash
   cd CTFoutu
   ```
3. Crée un environnement virtuel avec `pipenv` sans l'activer manuellement :
   ```bash
   pipenv install -r requirements.txt
   pipenv run ./ctfoutu.py "apache"
   ```
4. (Optionnel) Crée un lien symbolique ou un alias pour faciliter l'appel du programme :
   - Pour créer un alias :
     ```bash
     alias ctfoutu="pipenv run python ctfoutu.py"
     ```
   - Pour créer un lien symbolique :
     ```bash
     ln -s $(pwd)/ctfoutu.py /usr/local/bin/ctfoutu
     ```

## Utilisation

Pour utiliser CTFoutu, exécute le script avec un terme de recherche en argument ou passe le terme de recherche via un pipe. Ce terme peut être un mot-clé comme le nom d'un produit ou d'une technologie.

### Utilisation avec un argument

```bash
./ctfoutu.py "apache"
```

### Utilisation avec un pipe

```bash
echo "apache" | ./ctfoutu.py
```

L'outil affichera alors les CVEs et les exploits liés à "apache".

### Configurer la clé API

Pour configurer la clé API nécessaire à l'accès aux informations du NVD, utilise l'argument `--conf` :

```bash
./ctfoutu.py --conf
```

### Afficher l'aide

Pour afficher l'aide et la liste des options disponibles :

```bash
./ctfoutu.py --help
```

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

## Structure du Projet

- **ctfoutu.py** : Le script principal permettant de faire les recherches.
- **config.py** : Module permettant la configuration de la clé API pour accéder à la base de données NVD.
- **files\_exploits.csv** : Fichier contenant la base de données des exploits utilisée pour la recherche. Ce fichier est téléchargé temporairement.
- **requirements.txt** : Liste des dépendances nécessaires pour faire fonctionner le script.

## Contributions

Les contributions sont les bienvenues. N'hésite pas à proposer des correctifs ou de nouvelles fonctionnalités via des pull requests.

## Licence

Ce projet est distribué sous licence MIT. Consulte le fichier `LICENSE` pour plus de détails.

## Aide et Support

Si tu rencontres des problèmes ou as des questions concernant l'utilisation de cet outil, tu peux ouvrir une *issue* sur le dépôt GitHub.
