# Méthodologie

Ce document explique **comment Exposia raisonne** : l'architecture du pipeline, les choix d'algorithmique, puis chaque module, avec son rôle, ses entrées et sorties, sa logique et ses limites. Le code reste la référence ; ici on donne les clés pour le lire et le critiquer.

Exposia produit un rapport de **sensibilisation sans analyste** : il décrit l'exposition d'une organisation vue d'Internet, la hiérarchise, et propose des bonnes pratiques. Ce n'est ni un test d'intrusion ni un audit.

## Vocabulaire : cinq statuts d'information

Chaque information du rapport relève d'un de ces statuts, du plus factuel au plus interprétatif. Les lire dans cet ordre dit jusqu'où faire confiance à une ligne.

| Statut | Définition | Exemples dans Exposia | Origine |
|---|---|---|---|
| **Observé** | un fait relevé auprès d'une source | un sous-domaine découvert, une résolution DNS, un service signalé par une source, les valeurs CVSS et EPSS publiées | D1 |
| **Déduit** | une conclusion tirée d'un fait observé | une CVE associée à une version annoncée dans une bannière | D1 (Shodan) |
| **Estimé** | un calcul ou une présomption | la qualification et la criticité globale (§3), la nature interne/externe présumée | D1, D2 |
| **Modélisé** | un scénario construit à partir de règles et de matrices | un scénario d'attaque (§3.2), un profil de menace (D3) | D1, D3 |
| **Recommandé** | une action proposée | une mesure de mitigation | D2 |

Deux conséquences. D'abord, la confiance baisse à chaque statut : un sous-domaine observé est un fait, une CVE déduite peut être un faux positif (correctif rétroporté), une criticité estimée dépend de pondérations modifiables, un scénario modélisé est un cas type et non un incident, une mesure recommandée est une bonne pratique et non un correctif prouvé. Ensuite, le rapport rend ces statuts lisibles : « nature présumée », scénarios « types », mesures présentées comme bonnes pratiques.

## 1. Principes de conception

| Principe | Ce que ça change concrètement |
|---|---|
| **Passif** | Aucune requête d'exploitation ni scan de ports. Les sources sont les certificats publiés, le DNS public, Shodan, NVD, EPSS, ExploitDB et PoC-in-GitHub. |
| **Étages découplés** | Les modules communiquent par fichiers (CSV, JSON) dans `Result/<campagne>/data/`, jamais par appels entre eux. Un étage peut être relancé seul. |
| **Connaissance hors du code** | Ports, services, chemins d'attaque, mesures, plages de CDN et matrices de menaces sont des CSV éditables dans `Parameters/`. Adapter Exposia, c'est éditer des fichiers. |
| **Déterminisme** | À données identiques, résultat identique : tris stables, aléa initialisé par une empreinte (§3.1). Les sources externes évoluent, pas le calcul. |
| **Non destructif** | Les PDF intermédiaires sont conservés (`--clean` les supprime) ; la vue CSV finale est écrite dans un nouveau fichier. |
| **Une seule source de vérité** | Chemins (`exposia_paths`), clés API (`exposia_config`), console (`exposia_ui`) et thème PDF (`R0_report_theme`) sont centralisés. |
| **Honnêteté du rapport** | Les scénarios sont dits « types », la classification interne/externe « présumée », les CVE « déduites des versions annoncées ». |

### Accessible, adossé au détail

Exposia associe volontairement une vue d'ensemble du risque et l'accès aux constats sous-jacents. Le PDF offre une lecture concise, orientée décision, de la surface d'attaque externe ; l'export CSV conserve le détail nécessaire pour examiner chaque exposition, ses vulnérabilités, ses scénarios et ses mesures de mitigation.

La note globale est une aide à la priorisation, pas un substitut à l'examen des constats critiques. Ce compromis est voulu : rendre une évaluation de sécurité accessible suppose d'abstraire, sans retirer la possibilité d'investiguer les données.

## 2. Architecture

```
                      Parameters/  (CSV : ports, chemins, mesures, matrices, CVSS)
                           │
   domaine ──► D1 découverte ──► D2 mitigation ──► D3 menaces (interactif)
                │  Exposia_<domaine>.csv  │ + mesures    │ threat_analysis_*.csv
                │  run_summary.json       │              │
                ▼                         ▼              ▼
          R5 couverture   R7 avant-propos   R1 menaces   R2 actifs   R3 risques   R4 mitigation   R6 synthèse   R8 4ᵉ de couverture
                                   └─────────── PDF intermédiaires ───────────┘
                                                         ▼
                                       R9 assemblage ◄── R11 sommaire
                                                         ▼
                          Rapport_Final_*.pdf  +  R10 → Exposia_<domaine>_presentation.csv
```

**Fil conducteur de données.** D1 écrit un fichier de travail `Exposia_<domaine>.csv` au format *explosé* : une exposition, N récits d'attaque, N mesures de mitigation, soit une ligne par combinaison. D2 l'enrichit sur place (idempotent : relancé, il reconstitue les lignes de base avant de recommencer). Les modules R le lisent sans jamais le modifier. R10 le ré-agrège en une vue lisible : une ligne par exposition × CVE.

**Le tag, pivot sémantique.** Les récits d'attaque (`Ports_to_attack.csv`, étapes CVSS) et les mesures (`mitigation_measures.csv`) ne se connaissent pas : ils partagent des *tags* (`acces_non_authentifie`, `vol_donnees_sensibles`…). Un tag sans mesure laisserait un scénario sans réponse ; un test automatique vérifie que chaque tag utilisé a au moins une mesure.

**Interactivité.** Seule D3 pose des questions (secteur, taille, zone). La note ASM vient de D1 ; D3 ne la demande que si elle manque. `--skip-threat` saute l'étape.

## 3. Algorithmes transverses

### 3.1 Qualification d'une exposition

Chaque ligne (exposition, éventuellement avec une CVE) reçoit une qualification **Critical, High, Medium ou Low**. Quatre cas :

| Service connu | CVE | Calcul |
|---|---|---|
| oui | oui | `base × multiplicateur de service`, puis plancher exploit |
| non | oui | `base` seule, puis plancher exploit |
| oui | non | criticité du service seule : CRITIQUE ou HAUTE → Medium ; MOYENNE ou FAIBLE → Low |
| non | non | Low (score 0,1) |

```
base = 0,60 × EPSS + 0,25 × (CVSS / 10) + 0,15 × exp(−âge / 8)
```

- `âge` : années écoulées depuis l'année de la CVE (plancher du facteur : 0,05).
- Multiplicateur de service : CRITIQUE 1,3 ; HAUTE 1,1 ; MOYENNE 1,0 ; FAIBLE 0,8. Score plafonné à 1.
- Seuils : **Critical ≥ 0,75 ; High ≥ 0,55 ; Medium ≥ 0,35 ; sinon Low.**

*Pourquoi cette pondération.* EPSS, la probabilité d'exploitation observée, pèse le plus : une faille 9,8 jamais exploitée est moins urgente qu'une faille 8,1 exploitée à grande échelle. CVSS mesure la gravité, l'âge ajoute un léger poids aux failles récentes. Ces poids sont un **choix de conception, pas un standard**, à valider sur des cas réels.

**Plancher « exploit public ».** Une CVE pour laquelle au moins un exploit public est référencé (ExploitDB ou PoC-in-GitHub) n'est jamais qualifiée sous un plancher qui dépend de sa gravité : **High si CVSS ≥ 7, Medium sinon** (un CVSS inconnu compte pour 0). Le plancher relève une qualification, il ne l'abaisse jamais, et ne s'applique qu'aux lignes portant une CVE.

*Pourquoi ce plancher.* L'existence d'un exploit public est un fait observé, alors que l'EPSS est une estimation. Sans ce plancher, une faille ancienne et critique, exploitable clé en main mais à EPSS bas, pouvait finir en Low (par exemple CVSS 9,8, EPSS 0,02, CVE de 2016 sur un service HAUTE : score 0,33). Elle n'avait alors qu'un récit et aucune mesure. Le plancher est conditionné au CVSS pour ne pas porter en High une faille mineure dotée d'un simple PoC (par exemple CVSS 4,2, EPSS 0,002, un exploit référencé). Les règles sont réglables (`EXPLOIT_FLOOR_RULES` dans D1) ; une liste vide désactive le plancher.

### 3.2 Récit d'attaque : trois étapes, un plafond

Le récit d'une CVE suit le vecteur CVSS et se lit en trois phrases : **Reconnaissance → Exploitation → Impact**.

1. *Reconnaissance* : composante AV (réseau, adjacent, local…) → `CVSS_step1.csv`.
2. *Exploitation* : combinaison AC + PR + UI → `CVSS_step2.csv`. Pour une complexité élevée (AC:H), le texte précise que l'attaque suppose des circonstances favorables (position d'interception, course critique, configuration) : c'est le sens de AC:H, et il vaut aussi bien pour Terrapin (interception) que pour regreSSHion (course critique).
3. *Impact* : triplet C/I/A → `CVSS_step3.csv`, avec une criticité ; si le Scope est modifié (S:C), `CVSS_step3_attenuation.csv` ajoute un niveau.

Chaque étape fournit un texte et des tags. En plus du récit de la CVE, le service exposé reçoit des **scénarios génériques** (type PORT) tirés de `Ports_to_attack.csv`. Le nombre de récits est plafonné par qualification :

| Qualification | Récits par exposition |
|---|---|
| Critical | 3 |
| High | 2 |
| Medium | 1 |
| Low | 1 si CVE, sinon 0 |

Un récit CVE passe en premier, les scénarios PORT complètent. Ils sont choisis par un tirage **déterministe** : la graine est une empreinte MD5 des métadonnées de l'exposition (et non `hash()`, randomisé à chaque processus). Deux exécutions donnent donc les mêmes scénarios.

**Chaque exposition produit au moins une ligne.** Quand aucun récit n'est disponible, l'exposition est conservée sans récit (type `NONE`). C'est le cas d'un Low sans CVE, mais aussi d'un service connu sans CVE dont le port n'a pas de chemin d'attaque dans `Ports_to_attack.csv`. Elle reste ainsi visible dans l'inventaire des actifs et dans les décomptes du rapport.

### 3.3 Criticité globale du domaine

Une note unique, affichée en couverture et transmise à D3 comme note ASM :

```
score = (0,4 × CVSS moyen + 0,3 × EPSS moyen × 10 + 0,2 × ln(1 + exploits) + 0,1 × qualification moyenne × 10)
        × (1 + 0,05 × ln(1 + services par IP)) × (1 + 0,05 × ln(1 + vulnérabilités par IP))
```

Poids de qualification : Critical 1,0 ; High 0,7 ; Medium 0,4 ; Low 0,1. Seuils : **< 3 Low ; < 6 Medium ; < 9 High ; ≥ 9 Critical.**

La note est une moyenne, donc un actif critique y est dilué. **Plancher : dès qu'une exposition est Critical, la note globale n'est jamais inférieure à High.**

### 3.4 Scénarios et chiffres du rapport

Un **scénario** est un couple (CVE ou service, texte d'attaque). La synthèse annonce le nombre de scénarios *distincts* ; la colonne « Scénarios applicables » de chaque actif compte ceux qui le concernent, et leur somme peut dépasser le total : un même scénario générique concerne plusieurs actifs. La CVE fait partie de la clé d'unicité : deux CVE au texte identique restent deux scénarios.

### 3.5 Des métriques de lecture, pas une vérité absolue

CVSS, EPSS, KEV et la note d'Exposia sont des **grilles de lecture** : chacune répond à une question différente et aucune ne tranche seule.

| Métrique | Ce qu'elle dit | Ce qu'elle ne dit pas |
|---|---|---|
| CVSS | la gravité technique d'une faille | si elle est exploitée, ni si elle compte dans *votre* contexte |
| EPSS | une probabilité d'exploitation estimée | une exploitation constatée |
| KEV (CISA) | une exploitation constatée dans la nature | l'exposition de votre système, ni les failles pas encore cataloguées |
| Note Exposia | un ordre de lecture pour le périmètre | un niveau de risque réel |

Le volume de CVE publiées augmente, ce qui rend le filtrage plus nécessaire et plus fragile. Exposia combine donc CVSS et EPSS (§3.1), relevés par le plancher « exploit public », et **n'intègre pas encore KEV**. C'est la piste la plus directe : un signal binaire « exploité » ferait remonter une exposition sur la preuve et non sur l'estimation, sur le même modèle que le plancher exploit. Il ajouterait un appel réseau (§7) et modifierait la formule de qualification.

## 4. Modules de données (D)

### D1 : découverte et qualification

| | |
|---|---|
| **Entrée** | un domaine ; `services_list.csv`, `Ports_to_attack.csv`, `CVSS_step*.csv` ; clés API facultatives |
| **Sortie** | `Exposia_<domaine>.csv`, `run_summary.json` (criticité globale, métriques), fichiers intermédiaires (`resultats_shodan.csv`, `cve_identifies.csv`…) |

**Découverte.** crt.sh (journaux de transparence des certificats) donne les noms ; Cert Spotter prend le relais s'il ne répond pas. Un cache local évite de réinterroger crt.sh, qui limite le débit par IP et bloque en cas d'abus (le module gère les erreurs 429 et attend). Les noms sont nettoyés : jokers (`*.`), caractères invalides, hors du domaine. Chaque nom est résolu en DNS.

**Services et CVE.** Shodan, par IP, donne les ports ouverts et les CVE annoncées dans les bannières. Ces CVE sont **déduites des versions logicielles** : un correctif rétroporté peut les rendre fausses. Pour chaque CVE : CVSS et vecteur depuis NVD, EPSS depuis FIRST, exploits publics depuis ExploitDB (index téléchargé une fois par run) et PoC-in-GitHub. Les liens d'exploit sont dédoublonnés, pour que le nombre d'exploits d'une CVE corresponde au décompte d'exploits uniques du rapport. Sans clé NVD, la limite de 5 requêtes par 30 s impose environ 6 s par CVE ; avec une clé, 0,7 s.

**Sources indépendantes.** EPSS, PoC-in-GitHub et ExploitDB sont interrogés séparément : la panne de l'un n'efface jamais les données des autres. Une CVE est toujours conservée ; une source indisponible laisse simplement son champ vide (EPSS à `#N/A`, ou aucun lien d'exploit de cette source). Un bilan par source est affiché en fin de recherche. À noter : un EPSS manquant compte pour 0 dans la qualification (§3.1) et retire la ligne du calcul de la note globale (§3.3).

**Frontaux de CDN.** Derrière un CDN, les IP résolues sont celles des frontaux du fournisseur, partagées par tous ses clients. Les ports qu'ils ouvrent (2052, 2053, 2082, 2086, 8080, 8443, 8880…) et les CVE qu'y signale Shodan décrivent le CDN, pas l'organisation ; sans traitement, ils gonflaient le décompte des services (catégories « non catégorisé » ou « P2P » fantaisistes) et, par le volume, le classement des mesures. Une IP est reconnue comme frontal de CDN si elle appartient à une plage, ou à un AS, listé dans `Parameters/cdn_ranges.csv` (colonnes `Fournisseur;Plage`, la plage étant un réseau ou un numéro d'AS). L'ASN vient de la réponse Shodan déjà collectée, sans requête supplémentaire ; il couvre les adresses absentes des listes publiées (adresses apportées par un client du CDN, dites *BYOIP*, résolveur public). Pour un sous-domaine servi par un CDN, D1 ne garde qu'**une exposition par port web standard (80, 443)**, sans CVE, rattachée à une IP représentative (la plus petite, IPv4 d'abord). La colonne `Hosting` vaut alors `CDN <fournisseur>`, sinon `Direct`. Le bilan (sous-domaines et frontaux concernés) est inscrit dans `run_summary.json`. Ce qui reste visible est ce qui dépend de l'organisation : l'application servie derrière le CDN.

**Classification interne/externe.** Une *présomption* fondée sur des mots-clés du sous-domaine (`admin`, `dev`, `staging`…), des ports et des services d'ordinaire internes. Affichée comme « nature présumée », elle ne pondère plus le score, mais elle ordonne la matrice des actifs (partie 2 : les services présumés sensibles passent en tête). Les interfaces de conteneurs et d'orchestration en font partie : services `kubelet`, `kubernetes`, `etcd`, `docker` et ports 2375, 2376, 2379, 2380, 6443, 10250, 10255. Sans elles, une API kubelet exposée passait derrière les applications web dont le nom contient `adm` ou `staging`. Ces critères sont pour l'instant codés en dur dans D1 (`INTERNAL_SUBDOMAIN_KEYWORDS`, `INTERNAL_SERVICE_KEYWORDS`, `INTERNAL_PORTS`) ; ils ont vocation à devenir une colonne de `services_list.csv`, pour rester dans la logique « connaissance hors du code ».

**Choix à retenir.** D1 est le seul module qui accède au réseau (un test le vérifie) ; tout ce qui suit est calculé hors ligne à partir de ses fichiers. Le détail des requêtes est au §7.

### D2 : plan de mitigation

| | |
|---|---|
| **Entrée** | `Exposia_<domaine>.csv`, `mitigation_measures.csv` |
| **Sortie** | le même fichier enrichi ; `mitigation_prioritization_enhanced.csv` ; compteur dans `run_summary.json` |

**Sélection.** Les mesures sont retrouvées par tag, puis filtrées selon la qualification de l'exposition :

| Qualification | Priorités retenues | Types retenus |
|---|---|---|
| Critical | toutes | préventif, détectif, curatif |
| High | CRITIQUE, HAUTE | préventif + une seule détective |
| Medium | CRITIQUE, HAUTE | préventif |
| Low | aucune (sauf socle CVE) | aucun (sauf socle CVE) |

Une vulnérabilité est traitée selon **sa propre** qualification. Un périmètre qui ne compte que du Low est traité comme Medium, pour proposer tout de même quelques bonnes pratiques. Le niveau Medium est volontairement restreint : un tag sans mesure à ce niveau est couvert par les niveaux supérieurs, ce qui garde le plan lisible. Les doublons de mesure sont retirés.

**Socle CVE.** Une ligne qui porte une CVE ne reste jamais sans mesure. Si le filtrage n'en retient aucune (CVE qualifiée Low, ou CVE sans tags parce qu'elle n'a qu'un vecteur CVSS v2 ou pas de données NVD), elle reçoit la mesure de gestion des correctifs (`MIT-VULN-001`). Corriger une CVE, c'est d'abord mettre à jour le logiciel. La liste est réglable (`CVE_BASELINE_MITIGATION_IDS` dans D2) ; un identifiant absent de `mitigation_measures.csv` est signalé et ignoré. Les scénarios génériques (PORT) et les expositions sans CVE ne sont pas concernés.

**Classement des mesures.**

```
composite  = risque × efficacité × faisabilité
  risque      : Critical 4, High 3, Medium 2, Low 1
  efficacité  : priorité CRITIQUE 4, HAUTE 3, MOYENNE 2, FAIBLE 1
  faisabilité : difficulté Faible 4, Moyen 3, Élevé 2, Très élevé 1
exposition = (sous-domaine, port, CVE)
score final = composite maximal × ln(1 + expositions distinctes) × (1 + 0,1 × (types d'attaque − 1))
```

Le **niveau** d'une mesure est fixé par l'exposition la plus grave qu'elle traite ; la **couverture** (nombre d'expositions distinctes) départage. Deux choix, corrigés après un test réel :

- *Expositions distinctes, pas lignes.* Le fichier de travail est explosé (une ligne par récit, par IP, par mesure). Compter les lignes faisait gagner les mesures génériques appliquées à un service répliqué (CDN, round-robin DNS). L'IP ne fait pas partie de la clé : un sous-domaine servi par plusieurs adresses reste une exposition.
- *Maximum, pas moyenne.* La moyenne diluait une mesure traitant une CVE critique parmi des CVE mineures, et favorisait une mesure générique appliquée à beaucoup d'expositions moyennes. Sur le cas réel, une mesure de sensibilisation sans vulnérabilité associée passait devant la gestion des correctifs, alors qu'une CVE critique exploitée était exposée.

La colonne `avg_composite_score` de `mitigation_prioritization_enhanced.csv` garde son nom pour compatibilité mais contient le composite maximal ; `exposure_count` donne le nombre d'expositions distinctes.

### D3 : modélisation des menaces

| | |
|---|---|
| **Entrée** | secteur, taille, zone (saisie) ; note ASM (D1) ; matrices `Threat_matrices/M1..M7` |
| **Sortie** | `threat_analysis_*.csv`, une ligne par motivation retenue, avec `Score_Acteur` |

Inspirée de la taxonomie d'EBIOS RM : 8 sources de risque (Étatique, Crime organisé, Terroriste, Activiste, Officine, Amateur, Vengeur, Malveillant), 6 motivations. Pour chaque acteur :

1. **M1** : pertinence de l'acteur pour le secteur ; « Not relevant » l'exclut.
2. **M2** : niveau de motivation de l'acteur, pour chacune des 6 motivations.
3. **M3** : ressources de l'acteur selon la motivation.
4. **M4** : motivation × ressources → pertinence de la menace.
5. Seules les motivations « Very relevant » et « Quite relevant » sont **conservées** ; sans motivation retenue, l'acteur disparaît.
6. Score : `Score_Acteur = Σ (pertinence M1 × motivation × pertinence M4) × (M5 / 3) × (M6 / 3) × (M7 / 3)`.

Les matrices M5 (note ASM), M6 (taille) et M7 (zone) pondèrent de « Négligeable » (0) à « Très élevé » (5) ; 3 est neutre. Une pondération nulle annule le score et retire l'acteur.

Niveaux (lus par R1) : **Critique ≥ 300 ; Élevé ≥ 120 ; Modéré ≥ 40 ; sinon Faible.** Ces seuils ont été calibrés sur la distribution des 7 424 couples acteur/profil possibles ; à recalibrer si les matrices évoluent.

*Les matrices sont des jugements d'expert, modifiables, pas des mesures statistiques.*

## 5. Modules de rapport (R)

Chaque partie du rapport suit la **même structure**, pour que le lecteur s'y repère : un encadré « En clair » (l'essentiel en trois phrases), une « Méthodologie » courte, une matrice ou un tableau, puis le détail. La synthèse suffit pour décider ; les parties apportent le détail. Tous les modules partagent le thème de `R0_report_theme` : un changement de style se fait en un seul endroit.

| Module | Rôle | Choix méthodologique |
|---|---|---|
| **R5** couverture | Organisation, domaine, date, criticité globale | La criticité vient de D1 (§3.3). |
| **R7** avant-propos | « Ce que ce rapport dit, et ce qu'il ne dit pas » | Texte fixe : il décrit la méthode et ses limites, pas les résultats. |
| **R11** sommaire | Table des matières cliquable | Les numéros de page ne sont connus qu'à l'assemblage : R9 appelle R11 après avoir compté les pages. |
| **R6** synthèse | « De la menace à la mitigation » : trois chaînes acteur → actif → vecteur → mesure | Voir ci-dessous. |
| **R1** partie 1, menaces | Qui attaque, et pourquoi | Classe les acteurs par `Score_Acteur` (D3), avec leur profil (nombre de motivations). |
| **R2** partie 2, actifs | Quel périmètre est exposé | Sous-domaines, services, catégories ; classification affichée comme « nature présumée ». |
| **R3** partie 3, risques | Quels impacts | Top 10 des actifs : qualification, puis impact métier du service (criticité de `services_list.csv`), puis EPSS ; scénarios types ; trois scénarios affichés par actif. L'impact départage les actifs sans CVE (EPSS nul) : à qualification égale, un service d'administration critique passe devant une application web. |
| **R4** partie 4, mitigation | Que faire concrètement | Mesures présentées comme **bonnes pratiques** de sensibilisation : corriger une CVE, c'est mettre à jour le logiciel, et le rapport le dit en tête de partie. |
| **R8** quatrième de couverture | Clôture, confidentialité | Même fond que la couverture : les deux forment une paire. |
| **R9** assemblage | Fusion des PDF, numérotation, signets | Ordre fixe ; couverture et quatrième exclues de la numérotation ; PDF sources conservés par défaut. |
| **R10** vue présentation | Livrable CSV lisible | Une ligne par exposition × CVE : qualification la plus élevée du groupe, récits dédupliqués, mesures repliées (nombre, IDs, priorité maximale). |

**Ordre du rapport :** couverture, avant-propos, sommaire, synthèse, parties 1 à 4, quatrième de couverture.

**R6, construction des chaînes.** Les trois CVE distinctes les plus critiques (qualification, puis EPSS, comme en partie 3). L'acteur est le mieux classé de D3 dont une motivation correspond à l'impact : confidentialité → lucratif ou espionnage, disponibilité → entrave au fonctionnement, intégrité → influence. L'impact reprend le récit de la CVE ; la mesure est une mesure qui la traite (CRITIQUE d'abord), variée d'un scénario à l'autre.

**Un seul ordre de priorité.** Le « Focus sur les mesures prioritaires » de la synthèse reprend les trois premières mesures du classement de D2 (`final_score`), le même que la matrice et la « mesure prioritaire » de la partie 4. Auparavant, il listait les mesures citées dans les chaînes, si bien que la synthèse et la partie 4 ne recommandaient pas la même mesure en premier. Les chaînes, elles, gardent une mesure propre à chaque CVE.

**Sécurité des rapports.** Toutes les données externes (noms issus des certificats, bannières, textes de CVE) sont échappées avant d'entrer dans le HTML ; des tests injectent du `<script>` et vérifient le rendu.

## 6. Support

| Fichier | Rôle |
|---|---|
| `run_pipeline.sh` | Orchestrateur : enchaîne les étapes, options `--skip-*`, `--continue-on-error`, `--clean`. |
| `exposia_paths.py` | Arborescence unique, nom de campagne (domaine enregistré, sans suffixe public). |
| `exposia_config.py` | Clés API : variables d'environnement, sinon `config.yaml`. Jamais en argument. |
| `exposia_ui.py` | Affichage console (couleurs, statuts, barres) ; désactivé si la sortie est redirigée. |

## 7. Flux réseau et données transmises

Tout le trafic sortant vient de `D1_asset_discovery_assessment.py`. Un test (`test_only_d1_uses_network`) échoue si un autre module importe `requests`, `shodan` ou `socket`. Les rapports sont rendus hors ligne : polices embarquées, aucune ressource distante.

### 7.1 Requêtes émises

| Service | Requête | Donnée envoyée | Clé | Rôle |
|---|---|---|---|---|
| **crt.sh** | `GET crt.sh/?q=%25.<domaine>&output=json` (puis `q=<domaine>`) | le domaine | non | sous-domaines |
| **Cert Spotter** | `GET api.certspotter.com/v1/issuances?domain=<domaine>&include_subdomains=true&expand=dns_names` | le domaine | non | secours de crt.sh |
| **DNS** | `getaddrinfo(<sous-domaine>)` | chaque sous-domaine trouvé | non | adresses IP |
| **Shodan** | `api.info()` (test de clé), puis `api.host(<ip>)` par IP | chaque IP | **oui** (`SHODAN_API_KEY` ou `api_keys.shodan`) | ports, bannières, CVE annoncées, ASN |
| **NVD** | `GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` | un identifiant CVE | facultative (`NVD_API_KEY` ou `api_keys.nvd`), en en-tête `apiKey` | CVSS, vecteur, description |
| **EPSS (FIRST)** | `GET api.first.org/data/v1/epss?cve=<CVE>` | un identifiant CVE | non | probabilité d'exploitation |
| **PoC-in-GitHub** | `GET poc-in-github.motikan2010.net/api/v1/?cve_id=<CVE>` | un identifiant CVE | non | exploits publics |
| **ExploitDB** | `GET` du fichier `files_exploits.csv` (GitLab), une fois par exécution | rien (téléchargement) | non | correspondance CVE → exploit |

Rien d'autre n'est envoyé : ni contenu du rapport, ni nom d'organisation, ni secteur, ni réponses de D3. Les clés ne transitent que vers leur service, jamais en argument de ligne de commande.

### 7.2 Ce que ça implique

- **Pas d'interaction avec les services du périmètre**, sauf la **résolution DNS** : elle passe par votre résolveur et peut atteindre les serveurs de noms faisant autorité du domaine. C'est le seul contact, indirect, avec l'infrastructure ciblée. Aucun port n'est sondé, aucune bannière n'est lue en direct : Shodan restitue ce qu'il a déjà collecté.
- **Les tiers apprennent que vous vous intéressez au domaine** : crt.sh et Cert Spotter reçoivent le nom de domaine, Shodan les IP, NVD, EPSS et PoC-in-GitHub les CVE concernées. Tester un périmètre qui n'est pas le vôtre laisse donc des traces chez ces services.
- **Sans clé Shodan**, le scan est ignoré : le rapport contient les sous-domaines et IP, sans CVE. `--resolve-ips` limite l'exécution à la résolution DNS.
- **Sans clé NVD**, l'analyse reste complète mais lente : environ 6 s par CVE (limite publique du service, 5 requêtes par 30 s) contre 0,7 s avec une clé. D1 affiche une estimation de durée.
- **Caches locaux** : la liste des sous-domaines (`crtsh_cache_<domaine>.json`) est conservée dans `Result/<campagne>/data/` ; elle évite de réinterroger crt.sh à chaque exécution.
- **Identification** : NVD reçoit `User-Agent: CVE-Analyzer-Tool/1.0` ; les autres requêtes JSON se présentent avec un agent générique (`Mozilla/5.0`).

### 7.3 Conditions d'utilisation

Exposia n'embarque aucune donnée tierce ; chaque utilisateur interroge les services avec sa propre clé et reste responsable de respecter leurs conditions. Points d'attention :

| Service | À vérifier |
|---|---|
| Shodan | clé personnelle, quotas du plan, restrictions de redistribution des données (non redistribuées par Exposia) |
| NVD | limites de débit, mention obligatoire de non-approbation (reprise dans le README) |
| EPSS | citation de FIRST |
| CVSS | propriété de FIRST ; le score d'Exposia n'est pas un score CVSS officiel |
| crt.sh, Cert Spotter | services gratuits sans garantie ; limitation de débit par IP, la file d'attente est gérée (attente sur 429) |
| ExploitDB, PoC-in-GitHub | données publiques ; liens uniquement dans les rapports |

### 7.4 Usage responsable

Exposia est conçu pour votre propre périmètre ou pour un périmètre pour lequel vous avez une autorisation écrite. Même passive, la collecte relève de la reconnaissance : l'autorisation du propriétaire reste la règle.

## 8. Limites connues

- **Passif et tiers :** les données sont incomplètes et parfois en retard sur la réalité ; une CVE signalée peut être un faux positif.
- **CDN :** seuls les CDN listés dans `cdn_ranges.csv` sont reconnus (Cloudflare fourni). Un autre CDN (Akamai, Fastly, CloudFront…) gonfle encore le décompte tant qu'il n'y est pas ajouté, par plage ou par ASN. Une vraie exposition d'origine sur une IP de CDN (rare) serait réduite aux ports 80 et 443.
- **Critères « interne » codés en dur :** les mots-clés et ports qui définissent un service présumé sensible sont dans le code de D1, contrairement au reste du référentiel. Les adapter demande de modifier D1 tant qu'ils ne sont pas portés dans `services_list.csv`.
- **Classement des mesures :** le maximum fait remonter une mesure liée à une seule exposition grave ; la couverture ne départage qu'ensuite. Une mesure très générique reste haute si elle touche une exposition critique.
- **Pas de KEV :** l'exploitation confirmée n'entre pas dans la qualification ; une faille exploitée sans exploit public référencé et à EPSS bas peut être sous-classée (§3.5).
- **Plancher exploit :** un exploit public référencé n'est pas toujours fonctionnel (PoC incomplet, mauvaise version) ; le plancher peut donc surclasser une CVE. Le conditionner au CVSS limite l'effet aux failles graves. Le CVSS utilisé est celui que rapporte Shodan, qui peut différer de celui de NVD.
- **Calibrage :** pondérations (0,60 / 0,25 / 0,15), seuils (0,35 / 0,55 / 0,75), plancher exploit (High si CVSS ≥ 7, Medium sinon) et matrices M1..M7 sont des choix de conception, ouverts à validation empirique.
- **Aide à la décision :** le rapport n'est pas un audit et ne remplace pas un test d'intrusion.