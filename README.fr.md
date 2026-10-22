# Exposia

🇬🇧 [English version](README.md)

**Exposia transforme un nom de domaine en une vue structurée de son exposition cyber externe, avec des scénarios d'attaque illustratifs et des actions de remédiation priorisées. Son approche est déterministe, fondée sur des règles explicites, sans analyse générée par IA.**

Il collecte des données publiques de façon passive, applique une méthodologie documentée et produit un rapport PDF pour les décideurs, ainsi qu'un export CSV pour les analystes. La méthodologie est explicite et documentée : les principaux paramètres métier sont configurables, et les formules de score, hypothèses et limites peuvent être examinées.

Exposia sert à la sensibilisation à la sécurité et à l'aide à la décision. Ce n'est ni un outil de test d'intrusion ni un audit exhaustif.

▶ [Vidéo de démo (50 s)](https://www.youtube.com/watch?v=GNIJBMF6XgU)

> **Usage responsable.** N'évaluez que des domaines qui vous appartiennent ou pour lesquels vous disposez d'une autorisation explicite. La reconnaissance passive interroge tout de même des services tiers, et la résolution DNS peut atteindre indirectement les serveurs de noms faisant autorité du domaine. Les rapports décrivent l'exposition d'une organisation réelle : traitez-les comme confidentiels.

## Ce que vous obtenez

Pour chaque domaine, un dossier `Result/<nom>/` (`<nom>` est le domaine enregistré sans son suffixe, par exemple `example` pour `example.com`) contenant :

- `Rapport_Final_*.pdf` : couverture, synthèse, profils de menace, actifs, risques, plan de remédiation ;
- `Exposia_*_presentation.csv` : une ligne par exposition × CVE, prête pour un tableur ;
- `data/` : fichiers CSV et PDF intermédiaires, conservés pour examen.

Le rapport et le CSV sont générés **en français**. Le pipeline est décrit dans [Methodologie.md](Methodology/Methodologie.fr.md).

### Exemple de rendu

Le dossier [`Result/Exemple_FR/`](Result/Exemple_FR/) contient un exemple de rapport PDF et de fichiers d'export illustrant les résultats produits par Exposia.

Toutes les données de cet exemple sont entièrement fictives. L'organisation, les actifs, les vulnérabilités, les profils de menace et les scénarios présentés ont été inventés uniquement pour illustrer le rendu final. Ils ne correspondent à aucune analyse d'une organisation réelle et ne doivent pas être interprétés comme des résultats de sécurité vérifiés.

## Fonctionnalités principales

- **Découverte passive** : sous-domaines issus de la transparence des certificats, résolution DNS, services et bannières signalés par Shodan.
- **Qualification des vulnérabilités potentielles** : rapprochement des versions annoncées avec des CVE, puis priorisation selon l'EPSS, le CVSS, l'âge de la vulnérabilité et la criticité du service. Un seuil minimal de sévérité s'applique lorsqu'une référence d'exploit public est identifiée ; cette règle est configurable et peut conduire à une surestimation si la preuve de concept ne correspond pas à la version concernée ou n'est pas exploitable dans le contexte observé.
- **Scénarios d'attaque fondés sur des règles** : récits illustratifs dérivés des vecteurs CVSS et des services exposés.
- **Modélisation des menaces** : profils de menace issus de matrices configurables (secteur, taille, zone), inspirés d'EBIOS RM.
- **Recommandations de remédiation** : bonnes pratiques de sécurité classées selon le risque, l'efficacité et la faisabilité.
- **Configurable** : ports, services, correspondances d'attaque, mesures et matrices sont des fichiers CSV dans `Parameters/`.

## Installation

Python 3.10 ou supérieur.

```bash
git clone https://github.com/Or1un/Exposia/ && cd Exposia
pip install -r requirements.txt
chmod +x run_pipeline.sh
```

WeasyPrint nécessite des bibliothèques système (Pango). Voir son [guide d'installation](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html).

### Clés API

```bash
cp config.example.yaml config.yaml && chmod 600 config.yaml
```

Renseignez `api_keys.shodan` et `api_keys.nvd`, ou utilisez les variables d'environnement `SHODAN_API_KEY` et `NVD_API_KEY` (elles sont prioritaires).

- Sans clé Shodan, la découverte des sous-domaines et la résolution DNS restent disponibles, mais l'analyse des services et des CVE fondée sur Shodan est ignorée.
- Sans clé NVD, l'analyse prend environ 6 s par CVE au lieu de 0,7 s. [Clé gratuite](https://nvd.nist.gov/developers/request-an-api-key).

`config.yaml` est exclu du dépôt par `.gitignore`. Les clés ne sont jamais passées en ligne de commande.

## Utilisation

```bash
./run_pipeline.sh -d example.com
```

| Option | Effet |
|---|---|
| `--skip-threat` | Ignore la modélisation des menaces (la seule étape interactive) |
| `--skip-discovery --skip-mitigation` | Régénère le rapport à partir des données existantes |
| `--resolve-ips` | Résout les IP sans analyse de vulnérabilités |
| `--clean` | Supprime les PDF intermédiaires |
| `--continue-on-error` | Continue si une étape échoue |

`./run_pipeline.sh --help` liste toutes les options.

## Fonctionnement

1. **D1** : découvre les sous-domaines et les IP, puis les services et les CVE ; calcule les scores par exposition et pour le domaine.
2. **D2** : associe chaque constat à des mesures de remédiation et les classe.
3. **D3** : modélise les profils de menace pertinents à partir d'éléments de contexte et de matrices.
4. **Modules R** : génèrent et assemblent le rapport PDF et l'export CSV.

Les modules échangent des fichiers CSV et JSON : chaque étape peut être examinée et relancée seule. **Seul D1 accède à des services externes** ; les étapes suivantes travaillent sur les données collectées, et un test le vérifie.

Le score combine l'EPSS, le CVSS, l'âge de la vulnérabilité et la criticité du service. **Ce n'est pas un score CVSS officiel.** Les pondérations et les seuils sont des choix de conception, ni des standards du secteur ni des mesures validées statistiquement.

Chaque constat est étiqueté selon son statut épistémique : observé (donnée rapportée par une source), déduit (par exemple une CVE potentielle associée à une version annoncée), estimé (scores ou classifications heuristiques), modélisé (scénarios et profils de menace) ou recommandé (mesures de remédiation). Une vulnérabilité potentielle n'est pas une vulnérabilité confirmée, et un scénario modélisé n'est pas un incident. Le détail, les algorithmes et les notes par module sont dans [Methodologie.md](Methodology/Methodologie.fr.md).

## Sources de données

Exposia interroge ces services à l'exécution, avec vos propres clés. Aucune donnée tierce n'est redistribuée avec le dépôt. Vous restez responsable du respect des conditions de chaque service. Les requêtes émises et les données transmises à chaque service sont listées dans [Methodologie.md](Methodology/Methodologie.fr.md).

- [crt.sh](https://crt.sh) et [Cert Spotter](https://sslmate.com/certspotter) : transparence des certificats
- [Shodan](https://www.shodan.io) : services exposés (données © Shodan). Shodan restitue ce qu'il a déjà collecté ; Exposia ne scanne aucun port.
- [NVD](https://nvd.nist.gov) : scores CVSS. *This product uses the NVD API but is not endorsed or certified by the NVD.* (Ce produit utilise l'API NVD mais n'est ni approuvé ni certifié par le NVD.)
- [EPSS](https://www.first.org/epss) (FIRST) : probabilité d'exploitation
- [CVE](https://www.cve.org) : CVE® est une marque déposée de The MITRE Corporation
- [CVSS](https://www.first.org/cvss) : propriété de FIRST.Org, Inc., utilisé avec autorisation. Le score d'Exposia n'est pas un score CVSS officiel.
- [ExploitDB](https://gitlab.com/exploit-database/exploitdb) et [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) : références d'exploits publics et liens vers des preuves de concept. Exposia télécharge l'index public d'ExploitDB pour faire correspondre les CVE ; il ne télécharge ni code d'exploit ni charge utile de preuve de concept.
- Taxonomie des menaces inspirée d'[EBIOS RM](https://cyber.gouv.fr) (ANSSI), sans affiliation ni approbation.

## Limites

- **Faux positifs possibles** : les CVE sont déduites des versions annoncées ; des correctifs rétroportés peuvent les rendre fausses.
- **Visibilité incomplète** : les sources passives peuvent être incomplètes ou obsolètes. La prise en compte des CDN dépend des plages IP et des ASN configurés : certains actifs peuvent être sous-représentés, tandis que des fournisseurs non répertoriés peuvent entraîner des surestimations.
- **Heuristiques** : la classification interne/externe et les profils de menace reposent sur des règles configurables et un jugement d'expert.
- **Score non validé** : pondérations et seuils restent ouverts à un calibrage empirique.
- **Pas encore de signal KEV** : le catalogue CISA Known Exploited Vulnerabilities n'entre pas dans la qualification.
- **Ne remplace pas une évaluation professionnelle** : Exposia ne peut pas démontrer qu'un système est sûr.

## Contribuer

Les issues et pull requests sont les bienvenues, en particulier pour de nouveaux services ou chemins d'attaque dans `Parameters/`.
