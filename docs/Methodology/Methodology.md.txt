# Methodology

This document explains **how Exposia reasons**: the pipeline architecture, the algorithmic choices, then each module, with its role, inputs and outputs, logic and limitations. The code remains the reference; this document provides the keys to read and critique it.

Exposia produces an **analyst-free awareness report**: it describes an organization's exposure as seen from the Internet, prioritizes it, and suggests good practices. It is neither a penetration test nor an audit.

## Vocabulary: five information statuses

Every piece of information in the report has one of these statuses, from the most factual to the most interpretive. Reading them in this order tells you how far a given line can be trusted.

| Status | Definition | Examples in Exposia | Origin |
|---|---|---|---|
| **Observed** | a fact collected from a source | a discovered subdomain, a DNS resolution, a service reported by a source, published CVSS and EPSS values | D1 |
| **Inferred** | a conclusion drawn from an observed fact | a CVE associated with a version advertised in a banner | D1 (Shodan) |
| **Estimated** | a calculation or a presumption | the qualification and overall criticality (§3), the presumed internal/external nature | D1, D2 |
| **Modeled** | a scenario built from rules and matrices | an attack scenario (§3.2), a threat profile (D3) | D1, D3 |
| **Recommended** | a proposed action | a mitigation measure | D2 |

Two consequences. First, confidence drops with each status: an observed subdomain is a fact, an inferred CVE may be a false positive (backported fix), an estimated criticality depends on adjustable weights, a modeled scenario is a typical case and not an incident, a recommended measure is a good practice and not a proven fix. Second, the report makes these statuses visible: "presumed nature", "typical" scenarios, measures presented as good practices.

## 1. Design principles

| Principle | What it changes in practice |
|---|---|
| **Passive** | No exploitation requests and no port scanning. Sources are published certificates, public DNS, Shodan, NVD, EPSS, ExploitDB and PoC-in-GitHub. |
| **Decoupled stages** | Modules communicate through files (CSV, JSON) in `Result/<campaign>/data/`, never by calling each other. A stage can be rerun on its own. |
| **Knowledge outside the code** | Ports, services, attack paths, measures, CDN ranges and threat matrices are editable CSV files in `Parameters/`. Adapting Exposia means editing files. |
| **Determinism** | Same data, same result: stable sorting, randomness seeded by a hash (§3.1). External sources change; the computation does not. |
| **Non-destructive** | Intermediate PDFs are kept (`--clean` deletes them); the final CSV view is written to a new file. |
| **Single source of truth** | Paths (`exposia_paths`), API keys (`exposia_config`), console (`exposia_ui`) and PDF theme (`R0_report_theme`) are centralized. |
| **Report honesty** | Scenarios are labeled "typical", the internal/external classification "presumed", CVEs "inferred from advertised versions". |

### Accessible, backed by detail

Exposia deliberately combines an overview of risk with access to the underlying findings. The PDF offers a concise, decision-oriented reading of the external attack surface; the CSV export keeps the detail needed to examine each exposure, its vulnerabilities, its scenarios and its mitigation measures.

The overall rating is a prioritization aid, not a substitute for reviewing critical findings. This trade-off is intentional: making a security assessment accessible requires abstraction, without removing the ability to investigate the data.

## 2. Architecture

```
                      Parameters/  (CSV: ports, paths, measures, matrices, CVSS)
                           │
   domain ──► D1 discovery ──► D2 mitigation ──► D3 threats (interactive)
                │  Exposia_<domain>.csv  │ + measures   │ threat_analysis_*.csv
                │  run_summary.json      │              │
                ▼                        ▼              ▼
          R5 cover   R7 foreword   R1 threats   R2 assets   R3 risks   R4 mitigation   R6 summary   R8 back cover
                                   └─────────── intermediate PDFs ───────────┘
                                                         ▼
                                       R9 assembly ◄── R11 table of contents
                                                         ▼
                          Rapport_Final_*.pdf  +  R10 → Exposia_<domain>_presentation.csv
```

**Data thread.** D1 writes a working file `Exposia_<domain>.csv` in *exploded* format: one exposure, N attack narratives, N mitigation measures, i.e. one row per combination. D2 enriches it in place (idempotent: when rerun, it rebuilds the base rows before starting again). The R modules read it without ever modifying it. R10 re-aggregates it into a readable view: one row per exposure × CVE.

**Tags, the semantic pivot.** Attack narratives (`Ports_to_attack.csv`, CVSS steps) and measures (`mitigation_measures.csv`) do not know about each other: they share *tags* (`acces_non_authentifie`, `vol_donnees_sensibles`…). A tag without a measure would leave a scenario without a response; an automated test checks that every tag in use has at least one measure.

**Interactivity.** Only D3 asks questions (sector, size, region). The ASM rating comes from D1; D3 asks for it only if it is missing. `--skip-threat` skips the step.

## 3. Cross-cutting algorithms

### 3.1 Qualifying an exposure

Each row (an exposure, possibly with a CVE) receives a qualification of **Critical, High, Medium or Low**. Four cases:

| Known service | CVE | Calculation |
|---|---|---|
| yes | yes | `base × service multiplier`, then exploit floor |
| no | yes | `base` alone, then exploit floor |
| yes | no | service criticality alone: CRITIQUE or HAUTE → Medium; MOYENNE or FAIBLE → Low |
| no | no | Low (score 0.1) |

```
base = 0.60 × EPSS + 0.25 × (CVSS / 10) + 0.15 × exp(−age / 8)
```

- `age`: years elapsed since the CVE's year (factor floor: 0.05).
- Service multiplier: CRITIQUE 1.3; HAUTE 1.1; MOYENNE 1.0; FAIBLE 0.8. Score capped at 1.
- Thresholds: **Critical ≥ 0.75; High ≥ 0.55; Medium ≥ 0.35; otherwise Low.**

(Service criticality levels CRITIQUE / HAUTE / MOYENNE / FAIBLE are the values used in `services_list.csv`: critical / high / medium / low.)

*Why this weighting.* EPSS, the observed probability of exploitation, weighs the most: a 9.8 flaw that is never exploited is less urgent than an 8.1 flaw exploited at scale. CVSS measures severity; age adds slight weight to recent flaws. These weights are a **design choice, not a standard**, to be validated against real cases.

**"Public exploit" floor.** A CVE for which at least one public exploit is referenced (ExploitDB or PoC-in-GitHub) is never qualified below a floor that depends on its severity: **High if CVSS ≥ 7, Medium otherwise** (an unknown CVSS counts as 0). The floor raises a qualification, never lowers it, and only applies to rows carrying a CVE.

*Why this floor.* The existence of a public exploit is an observed fact, whereas EPSS is an estimate. Without this floor, an old, critical flaw that is exploitable off the shelf but has a low EPSS could end up as Low (for example CVSS 9.8, EPSS 0.02, a 2016 CVE on a HAUTE service: score 0.33). It then had only one narrative and no measure. The floor is conditioned on CVSS so that a minor flaw with a mere PoC is not raised to High (for example CVSS 4.2, EPSS 0.002, one referenced exploit). The rules are configurable (`EXPLOIT_FLOOR_RULES` in D1); an empty list disables the floor.

### 3.2 Attack narrative: three steps, one cap

A CVE's narrative follows the CVSS vector and reads as three sentences: **Reconnaissance → Exploitation → Impact**.

1. *Reconnaissance*: AV component (network, adjacent, local…) → `CVSS_step1.csv`.
2. *Exploitation*: AC + PR + UI combination → `CVSS_step2.csv`. For high complexity (AC:H), the text states that the attack requires favorable circumstances (interception position, race condition, configuration): that is what AC:H means, and it applies equally to Terrapin (interception) and regreSSHion (race condition).
3. *Impact*: C/I/A triplet → `CVSS_step3.csv`, with a criticality; if the Scope is changed (S:C), `CVSS_step3_attenuation.csv` adds one level.

Each step provides a text and tags. In addition to the CVE narrative, the exposed service receives **generic scenarios** (PORT type) drawn from `Ports_to_attack.csv`. The number of narratives is capped by qualification:

| Qualification | Narratives per exposure |
|---|---|
| Critical | 3 |
| High | 2 |
| Medium | 1 |
| Low | 1 if CVE, otherwise 0 |

A CVE narrative comes first; PORT scenarios fill in the rest. They are chosen by a **deterministic** draw: the seed is an MD5 hash of the exposure's metadata (and not `hash()`, which is randomized per process). Two runs therefore yield the same scenarios.

**Every exposure produces at least one row.** When no narrative is available, the exposure is kept without a narrative (type `NONE`). This is the case for a Low without a CVE, but also for a known service without a CVE whose port has no attack path in `Ports_to_attack.csv`. It thus remains visible in the asset inventory and in the report's counts.

### 3.3 Overall domain criticality

A single rating, shown on the cover and passed to D3 as the ASM rating:

```
score = (0.4 × mean CVSS + 0.3 × mean EPSS × 10 + 0.2 × ln(1 + exploits) + 0.1 × mean qualification × 10)
        × (1 + 0.05 × ln(1 + services per IP)) × (1 + 0.05 × ln(1 + vulnerabilities per IP))
```

Qualification weights: Critical 1.0; High 0.7; Medium 0.4; Low 0.1. Thresholds: **< 3 Low; < 6 Medium; < 9 High; ≥ 9 Critical.**

The rating is an average, so a critical asset gets diluted. **Floor: as soon as one exposure is Critical, the overall rating is never lower than High.**

### 3.4 Report scenarios and figures

A **scenario** is a pair (CVE or service, attack text). The executive summary reports the number of *distinct* scenarios; each asset's "Applicable scenarios" column counts those that concern it, and their sum can exceed the total: the same generic scenario applies to several assets. The CVE is part of the uniqueness key: two CVEs with identical text remain two scenarios.

### 3.5 Reading metrics, not absolute truth

CVSS, EPSS, KEV and the Exposia rating are **reading grids**: each answers a different question and none settles the matter alone.

| Metric | What it says | What it does not say |
|---|---|---|
| CVSS | the technical severity of a flaw | whether it is exploited, or whether it matters in *your* context |
| EPSS | an estimated probability of exploitation | an observed exploitation |
| KEV (CISA) | exploitation observed in the wild | your system's exposure, or flaws not yet catalogued |
| Exposia rating | a reading order for the perimeter | an actual risk level |

The volume of published CVEs is growing, which makes filtering both more necessary and more fragile. Exposia therefore combines CVSS and EPSS (§3.1), raised by the "public exploit" floor, and **does not yet integrate KEV**. That is the most direct improvement: a binary "exploited" signal would raise an exposure on evidence rather than estimate, on the same model as the exploit floor. It would add a network call (§7) and change the qualification formula.

## 4. Data modules (D)

### D1: discovery and qualification

| | |
|---|---|
| **Input** | a domain; `services_list.csv`, `Ports_to_attack.csv`, `CVSS_step*.csv`; optional API keys |
| **Output** | `Exposia_<domain>.csv`, `run_summary.json` (overall criticality, metrics), intermediate files (`resultats_shodan.csv`, `cve_identifies.csv`…) |

**Discovery.** crt.sh (Certificate Transparency logs) provides the names; Cert Spotter takes over if it does not respond. A local cache avoids querying crt.sh again, since it rate-limits per IP and blocks on abuse (the module handles 429 errors and waits). Names are cleaned: wildcards (`*.`), invalid characters, out-of-domain names. Each name is resolved via DNS.

**Services and CVEs.** Shodan, per IP, provides open ports and the CVEs advertised in banners. These CVEs are **inferred from software versions**: a backported fix can make them wrong. For each CVE: CVSS and vector from NVD, EPSS from FIRST, public exploits from ExploitDB (index downloaded once per run) and PoC-in-GitHub. Exploit links are deduplicated so that a CVE's exploit count matches the report's count of unique exploits. Without an NVD key, the limit of 5 requests per 30 s implies about 6 s per CVE; with a key, 0.7 s.

**Independent sources.** EPSS, PoC-in-GitHub and ExploitDB are queried separately: an outage of one never erases data from the others. A CVE is always kept; an unavailable source simply leaves its field empty (EPSS set to `#N/A`, or no exploit link from that source). A per-source summary is displayed at the end of the lookup. Note: a missing EPSS counts as 0 in the qualification (§3.1) and removes the row from the overall rating calculation (§3.3).

**CDN edge servers.** Behind a CDN, the resolved IPs belong to the provider's edge servers, shared by all its customers. The ports they open (2052, 2053, 2082, 2086, 8080, 8443, 8880…) and the CVEs Shodan reports on them describe the CDN, not the organization; left untreated, they inflated the service count (spurious "uncategorized" or "P2P" categories) and, through sheer volume, the ranking of measures. An IP is recognized as a CDN edge if it belongs to a range, or an AS, listed in `Parameters/cdn_ranges.csv` (columns `Fournisseur;Plage`, i.e. provider;range, the range being a network or an AS number). The ASN comes from the Shodan response already collected, with no extra request; it covers addresses missing from the published lists (addresses brought by a CDN customer, known as *BYOIP*, public resolvers). For a subdomain served by a CDN, D1 keeps only **one exposure per standard web port (80, 443)**, without CVEs, attached to a representative IP (the lowest, IPv4 first). The `Hosting` column is then set to `CDN <provider>`, otherwise `Direct`. The summary (affected subdomains and edge servers) is recorded in `run_summary.json`. What remains visible is what depends on the organization: the application served behind the CDN.

**Internal/external classification.** A *presumption* based on subdomain keywords (`admin`, `dev`, `staging`…), and on ports and services that are usually internal. Displayed as "presumed nature", it no longer weights the score, but it orders the asset matrix (part 2: services presumed sensitive come first). Container and orchestration interfaces are included: services `kubelet`, `kubernetes`, `etcd`, `docker` and ports 2375, 2376, 2379, 2380, 6443, 10250, 10255. Without them, an exposed kubelet API would rank behind web applications whose name contains `adm` or `staging`. These criteria are currently hard-coded in D1 (`INTERNAL_SUBDOMAIN_KEYWORDS`, `INTERNAL_SERVICE_KEYWORDS`, `INTERNAL_PORTS`); they are meant to become a column of `services_list.csv`, in keeping with the "knowledge outside the code" principle.

**Key takeaway.** D1 is the only module that accesses the network (a test checks this); everything downstream is computed offline from its files. Request details are in §7.

### D2: mitigation plan

| | |
|---|---|
| **Input** | `Exposia_<domain>.csv`, `mitigation_measures.csv` |
| **Output** | the same file, enriched; `mitigation_prioritization_enhanced.csv`; counter in `run_summary.json` |

**Selection.** Measures are matched by tag, then filtered according to the exposure's qualification:

| Qualification | Priorities kept | Types kept |
|---|---|---|
| Critical | all | preventive, detective, corrective |
| High | CRITIQUE, HAUTE | preventive + a single detective one |
| Medium | CRITIQUE, HAUTE | preventive |
| Low | none (except CVE baseline) | none (except CVE baseline) |

A vulnerability is handled according to **its own** qualification. A perimeter containing only Low is treated as Medium, so that a few good practices are still proposed. The Medium level is deliberately restricted: a tag without a measure at this level is covered by the higher levels, which keeps the plan readable. Duplicate measures are removed.

**CVE baseline.** A row carrying a CVE is never left without a measure. If filtering keeps none (CVE qualified Low, or CVE without tags because it only has a CVSS v2 vector or no NVD data), it receives the patch management measure (`MIT-VULN-001`). Fixing a CVE means, first and foremost, updating the software. The list is configurable (`CVE_BASELINE_MITIGATION_IDS` in D2); an identifier missing from `mitigation_measures.csv` is reported and ignored. Generic (PORT) scenarios and exposures without a CVE are not affected.

**Ranking measures.**

```
composite  = risk × effectiveness × feasibility
  risk          : Critical 4, High 3, Medium 2, Low 1
  effectiveness : priority CRITIQUE 4, HAUTE 3, MOYENNE 2, FAIBLE 1
  feasibility   : difficulty Faible (low) 4, Moyen (medium) 3, Élevé (high) 2, Très élevé (very high) 1
exposure = (subdomain, port, CVE)
final score = maximum composite × ln(1 + distinct exposures) × (1 + 0.1 × (attack types − 1))
```

A measure's **level** is set by the most severe exposure it addresses; **coverage** (number of distinct exposures) breaks ties. Two choices, corrected after a real-world test:

- *Distinct exposures, not rows.* The working file is exploded (one row per narrative, per IP, per measure). Counting rows favored generic measures applied to a replicated service (CDN, DNS round-robin). The IP is not part of the key: a subdomain served by several addresses remains one exposure.
- *Maximum, not average.* The average diluted a measure addressing a critical CVE among minor ones, and favored a generic measure applied to many medium exposures. In the real case, an awareness measure with no associated vulnerability ranked ahead of patch management, while an exploited critical CVE was exposed.

The `avg_composite_score` column of `mitigation_prioritization_enhanced.csv` keeps its name for compatibility but contains the maximum composite; `exposure_count` gives the number of distinct exposures.

### D3: threat modeling

| | |
|---|---|
| **Input** | sector, size, region (user input); ASM rating (D1); `Threat_matrices/M1..M7` matrices |
| **Output** | `threat_analysis_*.csv`, one row per retained motivation, with `Score_Acteur` |

Inspired by the EBIOS RM taxonomy: 8 risk sources (State-sponsored, Organized crime, Terrorist, Activist, Specialized outfit, Amateur, Avenger, Malicious/pathological), 6 motivations. For each actor:

1. **M1**: relevance of the actor to the sector; "Not relevant" excludes it.
2. **M2**: the actor's motivation level for each of the 6 motivations.
3. **M3**: the actor's resources depending on the motivation.
4. **M4**: motivation × resources → threat relevance.
5. Only "Very relevant" and "Quite relevant" motivations are **kept**; with no motivation kept, the actor is dropped.
6. Score: `Score_Acteur = Σ (M1 relevance × motivation × M4 relevance) × (M5 / 3) × (M6 / 3) × (M7 / 3)`.

Matrices M5 (ASM rating), M6 (size) and M7 (region) apply weights from "Negligible" (0) to "Very high" (5); 3 is neutral. A zero weight cancels the score and removes the actor.

Levels (read by R1): **Critical ≥ 300; High ≥ 120; Moderate ≥ 40; otherwise Low.** These thresholds were calibrated on the distribution of the 7,424 possible actor/profile pairs; they should be recalibrated if the matrices change.

*The matrices are expert judgments, editable, not statistical measurements.*

## 5. Report modules (R)

Every part of the report follows **the same structure**, so the reader can find their way: an "In plain terms" box (the essentials in three sentences), a short "Methodology", a matrix or table, then the detail. The executive summary is enough to make a decision; the parts provide the detail. All modules share the `R0_report_theme` theme: a style change is made in one place.

| Module | Role | Methodological choice |
|---|---|---|
| **R5** cover | Organization, domain, date, overall criticality | Criticality comes from D1 (§3.3). |
| **R7** foreword | "What this report says, and what it does not" | Fixed text: it describes the method and its limits, not the results. |
| **R11** table of contents | Clickable table of contents | Page numbers are only known at assembly: R9 calls R11 after counting pages. |
| **R6** executive summary | "From threat to mitigation": three actor → asset → vector → measure chains | See below. |
| **R1** part 1, threats | Who attacks, and why | Ranks actors by `Score_Acteur` (D3), with their profile (number of motivations). |
| **R2** part 2, assets | What perimeter is exposed | Subdomains, services, categories; classification shown as "presumed nature". |
| **R3** part 3, risks | What impacts | Top 10 assets: qualification, then the service's business impact (criticality from `services_list.csv`), then EPSS; typical scenarios; three scenarios shown per asset. Impact breaks ties between assets without CVEs (zero EPSS): at equal qualification, a critical administration service ranks ahead of a web application. |
| **R4** part 4, mitigation | What to do in practice | Measures presented as awareness **good practices**: fixing a CVE means updating the software, and the report says so at the start of the part. |
| **R8** back cover | Closing, confidentiality | Same background as the cover: the two form a pair. |
| **R9** assembly | PDF merging, page numbering, bookmarks | Fixed order; cover and back cover excluded from numbering; source PDFs kept by default. |
| **R10** presentation view | Readable CSV deliverable | One row per exposure × CVE: highest qualification in the group, deduplicated narratives, folded measures (count, IDs, maximum priority). |

**Report order:** cover, foreword, table of contents, executive summary, parts 1 to 4, back cover.

**R6, building the chains.** The three most critical distinct CVEs (qualification, then EPSS, as in part 3). The actor is the highest-ranked one from D3 with a motivation matching the impact: confidentiality → financial gain or espionage, availability → disruption of operations, integrity → influence. The impact reuses the CVE narrative; the measure is one that addresses it (CRITIQUE first), varied from one scenario to the next.

**A single priority order.** The executive summary's "Focus on priority measures" takes the first three measures from D2's ranking (`final_score`), the same as the matrix and the "priority measure" of part 4. Previously it listed the measures cited in the chains, so the summary and part 4 did not recommend the same measure first. The chains still keep a measure specific to each CVE.

**Report security.** All external data (names from certificates, banners, CVE texts) is escaped before entering the HTML; tests inject `<script>` and check the rendering.

## 6. Support

| File | Role |
|---|---|
| `run_pipeline.sh` | Orchestrator: chains the steps, options `--skip-*`, `--continue-on-error`, `--clean`. |
| `exposia_paths.py` | Single directory tree, campaign name (registered domain, without public suffix). |
| `exposia_config.py` | API keys: environment variables, otherwise `config.yaml`. Never as arguments. |
| `exposia_ui.py` | Console display (colors, statuses, progress bars); disabled when output is redirected. |

## 7. Network flows and transmitted data

All outbound traffic comes from `D1_asset_discovery_assessment.py`. A test (`test_only_d1_uses_network`) fails if any other module imports `requests`, `shodan` or `socket`. Reports are rendered offline: embedded fonts, no remote resources.

### 7.1 Requests sent

| Service | Request | Data sent | Key | Role |
|---|---|---|---|---|
| **crt.sh** | `GET crt.sh/?q=%25.<domain>&output=json` (then `q=<domain>`) | the domain | no | subdomains |
| **Cert Spotter** | `GET api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names` | the domain | no | crt.sh fallback |
| **DNS** | `getaddrinfo(<subdomain>)` | each subdomain found | no | IP addresses |
| **Shodan** | `api.info()` (key check), then `api.host(<ip>)` per IP | each IP | **yes** (`SHODAN_API_KEY` or `api_keys.shodan`) | ports, banners, advertised CVEs, ASN |
| **NVD** | `GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` | a CVE identifier | optional (`NVD_API_KEY` or `api_keys.nvd`), in the `apiKey` header | CVSS, vector, description |
| **EPSS (FIRST)** | `GET api.first.org/data/v1/epss?cve=<CVE>` | a CVE identifier | no | exploitation probability |
| **PoC-in-GitHub** | `GET poc-in-github.motikan2010.net/api/v1/?cve_id=<CVE>` | a CVE identifier | no | public exploits |
| **ExploitDB** | `GET` of the `files_exploits.csv` file (GitLab), once per run | nothing (download) | no | CVE → exploit mapping |

Nothing else is sent: no report content, no organization name, no sector, no D3 answers. Keys are only sent to their own service, never as command-line arguments.

### 7.2 What this implies

- **No interaction with the services in scope**, except **DNS resolution**: it goes through your resolver and may reach the domain's authoritative name servers. This is the only contact, indirect, with the targeted infrastructure. No port is probed, no banner is read directly: Shodan returns what it has already collected.
- **Third parties learn that you are interested in the domain**: crt.sh and Cert Spotter receive the domain name, Shodan the IPs, NVD, EPSS and PoC-in-GitHub the relevant CVEs. Testing a perimeter that is not yours therefore leaves traces with these services.
- **Without a Shodan key**, the scan is skipped: the report contains subdomains and IPs, without CVEs. `--resolve-ips` limits the run to DNS resolution.
- **Without an NVD key**, the analysis remains complete but slow: about 6 s per CVE (the service's public limit, 5 requests per 30 s) versus 0.7 s with a key. D1 displays a duration estimate.
- **Local caches**: the subdomain list (`crtsh_cache_<domain>.json`) is kept in `Result/<campaign>/data/`; it avoids querying crt.sh on every run.
- **Identification**: NVD receives `User-Agent: CVE-Analyzer-Tool/1.0`; other JSON requests use a generic agent (`Mozilla/5.0`).

### 7.3 Terms of use

Exposia ships no third-party data; each user queries the services with their own key and remains responsible for complying with their terms. Points of attention:

| Service | What to check |
|---|---|
| Shodan | personal key, plan quotas, data redistribution restrictions (data not redistributed by Exposia) |
| NVD | rate limits, mandatory non-endorsement notice (included in the README) |
| EPSS | FIRST citation |
| CVSS | property of FIRST; the Exposia score is not an official CVSS score |
| crt.sh, Cert Spotter | free services with no guarantee; per-IP rate limiting, queueing is handled (wait on 429) |
| ExploitDB, PoC-in-GitHub | public data; links only in reports |

### 7.4 Responsible use

Exposia is designed for your own perimeter or for a perimeter for which you have written authorization. Even when passive, collection is reconnaissance: the owner's authorization remains the rule.

## 8. Known limitations

- **Passive and third-party:** data is incomplete and sometimes lags behind reality; a reported CVE may be a false positive.
- **CDN:** only CDNs listed in `cdn_ranges.csv` are recognized (Cloudflare provided). Another CDN (Akamai, Fastly, CloudFront…) still inflates the count until it is added, by range or by ASN. A genuine origin exposure on a CDN IP (rare) would be reduced to ports 80 and 443.
- **Hard-coded "internal" criteria:** the keywords and ports that define a service presumed sensitive are in D1's code, unlike the rest of the reference data. Adapting them requires modifying D1 until they are moved into `services_list.csv`.
- **Measure ranking:** the maximum raises a measure tied to a single severe exposure; coverage only breaks ties afterwards. A very generic measure stays high if it touches a critical exposure.
- **No KEV:** confirmed exploitation does not enter the qualification; a flaw exploited in the wild with no referenced public exploit and a low EPSS may be under-ranked (§3.5).
- **Exploit floor:** a referenced public exploit is not always functional (incomplete PoC, wrong version); the floor can therefore over-rank a CVE. Conditioning it on CVSS limits the effect to severe flaws. The CVSS used is the one reported by Shodan, which may differ from NVD's.
- **Calibration:** weights (0.60 / 0.25 / 0.15), thresholds (0.35 / 0.55 / 0.75), exploit floor (High if CVSS ≥ 7, Medium otherwise) and matrices M1..M7 are design choices, open to empirical validation.
- **Decision aid:** the report is not an audit and does not replace a penetration test.