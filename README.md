# BAIT — Bayesian Architectures for Interpretable Insider Threat Detection

> **BAIT: Bayesian Architectures for Interpretable Insider Threat Detection**
> Matheus V. P. dos Santos, José Edson C. A. Júnior, Damião de O. M. Neto, Pedro H. G. Liberal, Anderson M. de Morais, Milton Lima, J. R. Campos, Fernando Aires, Wellison R. M. Santos
> CISSA (Centro Integrado de Segurança em Sistemas Avançados) / CESAR School, Recife, Brazil
> CISUC — Centre for Informatics and Systems, University of Coimbra, Portugal
> *Funded by EMBRAPII — Project CIS-AFCCT-2024-7-26-2*
> *IEEE Access, submitted June 25, 2026*

---

## Overview

Insider threats represent a critical challenge in organizational cybersecurity: malicious actors with legitimate access can cause significant damage while evading conventional detection mechanisms, and security teams must be able to justify why a given user was flagged before escalating an investigation.

**BAIT** (Bayesian Architectures for Insider Threat Detection) is a probabilistic framework that evaluates **six alternative Bayesian-network architectures** for user-level insider threat detection under a single, unified preprocessing and evaluation protocol, rather than assuming that one manually specified dependency pattern is always optimal. All architectures share:

- Multi-source **behavioral feature engineering** (logon, device, e-mail, file, and Web activity)
- **Mutual-Information (MI)** based feature selection
- **Train-fitted discretization** (no test-set leakage)
- **MAP estimation with a BDeu prior**, with the equivalent sample size (ESS) itself selected empirically on a validation split, not fixed a priori
- **Validation-based threshold calibration**, using a single canonical criterion (Youden's J) applied everywhere in the pipeline
- A **leakage-aware evaluation protocol**: the 30-fold architecture-selection cross-validation pools only the training partition, and the held-out test set is touched exactly once, for the final canonical result

The winning architecture is selected empirically (not fixed a priori) through a 30-run repeated stratified cross-validation comparison restricted to the training partition, giving security analysts an auditable, interpretable evidence path — the graph structure, the CPTs, and the posterior risk score — behind every alert.

---

## Evaluated Bayesian Architectures

BAIT compares six architectures, built from the same preprocessed (discretized + latent) feature set:

| Key | Architecture | Description |
|-----|--------------|-------------|
| `NB` | Naive Bayes | Label → every feature; features conditionally independent given the class. Classical baseline. |
| `SNBN` | Semi-Naive (SIND) | Naive Bayes backbone plus a fixed intra-domain feature chain (manually defined local dependencies). |
| `HL` | Hierarchical Latent (fixed) | Label → latent domain node (K-Means summary) → domain features; no learned structure among latents. |
| **`TAN-F`** | **TAN over Features (Chow-Liu)** | Label → every feature, plus a Chow-Liu maximum-mutual-information spanning tree learned directly among the *observed* behavioral features (Tree-Augmented Naive Bayes). |
| `SIND-CL` | SIND + Latent Structure (Chow-Liu) | Latent/domain-level dependencies learned with the Chow-Liu algorithm. |
| `SIND-HC` | SIND + Latent Structure (HillClimb/BIC) | Latent/domain-level dependencies learned via greedy hill-climbing search scored with BIC. |

`SIND-CL` and `SIND-HC` are architecturally identical except for *how* the inter-domain (latent-latent) dependencies are discovered. A dedicated diagnostic (Section 7.3 of the notebook) checks, fold by fold, whether the two techniques actually learn different graphs: across 30 folds, the undirected skeleton matches in 29 of them, but the directed edge orientation matches in only 7, confirming the two variants are not simply computing the same structure twice.

**TAN-F (TAN over Features, learned with Chow-Liu) was selected as the best overall architecture** across the 30-fold repeated cross-validation comparison, and is the architecture reported for the single-run auditable evaluation.

> **Note on causal language.** Edges represent probabilistic dependencies informed by data and by domain structure, not verified causal relationships.

---

## Key Results (CERT r4.2)

### 30-run repeated stratified cross-validation (primary architecture-selection evidence, `X_train` only)

| Architecture | Edges | Acc. | Precision | Recall | F1 | FPR | AUPRC |
|---|---|---|---|---|---|---|---|
| Naive Bayes | 24 | 0.9688 ± 0.0170 | 0.9280 ± 0.0457 | 0.9800 ± 0.0252 | 0.9524 ± 0.0253 | 0.0363 ± 0.0246 | 0.9830 ± 0.0178 |
| Semi-Naive (SIND) | 43 | 0.9867 ± 0.0124 | 0.9713 ± 0.0280 | **0.9878 ± 0.0251** | 0.9791 ± 0.0195 | 0.0138 ± 0.0139 | **0.9980 ± 0.0024** |
| Hierarchical Latent (fixed) | 28 | 0.8843 ± 0.0517 | 0.7981 ± 0.1159 | 0.8967 ± 0.0772 | 0.8350 ± 0.0562 | 0.1214 ± 0.0952 | 0.9276 ± 0.0418 |
| **TAN-F** | 47 | **0.9881 ± 0.0111** | **0.9816 ± 0.0198** | 0.9811 ± 0.0307 | **0.9810 ± 0.0180** | **0.0087 ± 0.0095** | 0.9977 ± 0.0053 |
| SIND + Latent (Chow-Liu) | 31 | 0.9103 ± 0.0307 | 0.8313 ± 0.0654 | 0.9067 ± 0.0533 | 0.8652 ± 0.0432 | 0.0880 ± 0.0412 | 0.9499 ± 0.0294 |
| SIND + Latent (HillClimb/BIC) | 31 | 0.9103 ± 0.0307 | 0.8313 ± 0.0654 | 0.9067 ± 0.0533 | 0.8652 ± 0.0432 | 0.0880 ± 0.0412 | 0.9498 ± 0.0293 |

Paired Wilcoxon signed-rank tests show TAN-F is significantly better than Naive Bayes (p = 0.0002), the fixed hierarchical latent architecture, and both latent-structure variants (p < 0.0001); the comparison against Semi-Naive (SIND) is directionally favorable but essentially a tie and not statistically significant (p = 0.9810, ΔF1 = 0.0018). TAN-F is selected for its stronger overall balance of F1, precision, and the lowest FPR among all six architectures, rather than for statistically dominating every comparison.

### Single held-out run — selected architecture (TAN-F, BDeu ESS = 10)

Evaluated on a strictly imbalanced held-out test set (279 normal / 21 malicious, 7.00% malicious rate) to reflect a realistic needle-in-a-haystack scenario. The BDeu equivalent sample size (ESS = 10) used here was selected beforehand on an independent validation split via AUPRC (Section 8 of the notebook), not fit to this test set.

| TP | FP | TN | FN | Threshold | Acc. | Precision | Recall | F1 | FPR | AUC-ROC | AUPRC |
|----|----|----|----|-----------|------|-----------|--------|----|----|---------|--------|
| 20 | 1 | 278 | 1 | 0.71 | 0.9933 | 0.9524 | 0.9524 | 0.9524 | 0.0036 | 0.9995 | 0.9936 |

---

## Architecture

BAIT operates as an end-to-end pipeline:

`Raw Activity Logs → Feature Engineering → MI Feature Selection → Train-Fitted Discretization → Bayesian Architecture → BDeu ESS Selection (Train2/Val) → Threshold Calibration → Classification`

1. **Feature Engineering** — raw event streams (authentication, device, e-mail, file, Web) are aggregated into user-level behavioral profiles.
2. **MI Feature Selection** — Mutual Information ranks candidate variables and retains a compact 24-feature subset.
3. **Train-Fitted Discretization** — continuous features are binned using boundaries fit only on the training partition (no test leakage).
4. **Bayesian Architecture** — one of six architectures (see above) is trained via MAP estimation with a BDeu prior; architecture selection (30-fold CV) uses `X_train` only.
5. **BDeu ESS Selection** — the equivalent sample size is chosen on an inner `Train2`/`Val` split (still inside `X_train`) via validation AUPRC, rather than fixed a priori.
6. **Threshold Calibration & Classification** — posterior probabilities `P(Label = 1 | evidence)` are converted into binary alerts using a single canonical criterion, Youden's J, calibrated on validation and applied once to `X_test`.

---

## Selected Features

The 24 features used by BAIT are derived via Mutual Information analysis across five behavioral domains.

| Feature | Description |
|---------|-------------|
| `device_std_daily_device_events` | Standard deviation of the daily number of device events. |
| `device_mean_daily_device_events` | Daily mean number of device events. |
| `device_max_daily_device_events` | Maximum number of device events on a single day. |
| `device_device_events_total` | Total number of device events. |
| `device_offhour_device_ratio` | Proportion of device events outside working hours relative to the total. |
| `device_offhour_device_count` | Absolute number of device events outside working hours. |
| `device_active_days` | Number of days on which device activity occurred. |
| `device_unique_pcs_used` | Number of distinct computers used by the user. |
| `device_usb_connects` | Number of USB device connections. |
| `logon_total_logons_day` | Total number of daily logons. |
| `logon_total_logoffs_day` | Total number of daily logoffs. |
| `logon_sessions_total_duration` | Total duration of logon sessions. |
| `logon_open_sessions_mean` | Mean number of simultaneously open sessions. |
| `logon_missing_logoff_count` | Number of logons without a corresponding logoff. |
| `logon_logon_to_logoff_ratio` | Ratio between logons and logoffs. |
| `logon_distinct_pcs_used` | Number of distinct computers accessed through logon. |
| `email_n_email` | Total number of e-mails sent and received. |
| `email_email_total_attachments` | Total number of attachments in e-mails. |
| `email_email_unique_bcc` | Number of unique recipients in blind carbon copy. |
| `email_email_unique_to` | Number of unique recipients in the To field. |
| `email_email_mean_text_len` | Mean text length of e-mails. |
| `file_pdf_files_accessed` | Number of PDF files accessed. |
| `file_exe_files_accessed` | Number of executable files accessed. |
| `http_unique_urls_visited` | Number of unique HTTP URLs visited. |

---

## Repository Contents

```
BAIT/
├── Extração de Features.ipynb                  # Step 1 — raw CERT r4.2 logs → user-level feature matrix
├── BAIT_Pipeline_v4_MultiArchitecture.ipynb    # Step 2 — architecture comparison, calibration & final evaluation
├── 4.2_meses_18.zip                            # Preprocessed CERT r4.2 splits (output of Step 1)
│   ├── X_train.csv
│   ├── X_test.csv
│   ├── y_train.csv
│   └── y_test.csv
└── README.md
```

The two notebooks form a sequential pipeline: **`Extração de Features`** processes the raw CERT r4.2 CSV logs into a per-user behavioral feature matrix, and **`BAIT_Pipeline_v4_MultiArchitecture`** consumes that matrix to build, train, calibrate, and compare all six Bayesian architectures, selecting the best one and reproducing every table and figure reported in the manuscript.

---

## Getting Started

### Prerequisites

- Python 3.8+ (pipeline was profiled on Python 3.12)
- Jupyter Notebook or Google Colab
- Raw CERT r4.2 logs (required only if re-running feature extraction — see Option B)

### Installation

```bash
pip install pgmpy scikit-learn imbalanced-learn scipy networkx seaborn matplotlib pandas numpy
```

Or in a Colab/notebook cell:

```python
!pip install pgmpy scikit-learn imbalanced-learn scipy networkx seaborn
```

### Option A — Run from preprocessed splits (recommended)

Use the included `4.2_meses_18.zip` to reproduce the BAIT results without re-extracting features.

1. Clone the repository:
   ```bash
   git clone https://github.com/CESAR-CISSA/SIND.git
   cd SIND
   ```
   > The repository name is retained from the original codebase for continuity; it now hosts the BAIT architecture-comparison pipeline.

2. Extract the dataset:
   ```bash
   unzip 4.2_meses_18.zip
   ```

3. Open and run the main notebook:
   ```bash
   jupyter notebook "BAIT_Pipeline_v4_MultiArchitecture.ipynb"
   ```

   The notebook expects the following files in its working directory (generated by `Extração de Features.ipynb`):
   ```python
   X_train = pd.read_csv('./X_train.csv')
   X_test  = pd.read_csv('./X_test.csv')
   y_train = pd.read_csv('./y_train.csv').squeeze()
   y_test  = pd.read_csv('./y_test.csv').squeeze()
   ```

### Option B — Full pipeline from raw logs

To reproduce everything from scratch starting from the original CERT r4.2 event logs:

1. Download the raw CERT r4.2 dataset (see [Dataset](#dataset)) and place the CSVs under `/srv/cert/r4.2/`:
   ```
   /srv/cert/r4.2/
   ├── device.csv
   ├── logon.csv
   ├── file.csv
   ├── email.csv
   └── http.csv
   ```

2. Run **`Extração de Features.ipynb`**. The notebook parses each event source, computes per-user behavioral aggregates, joins all domain tables on `user`, and assigns binary labels from the ground-truth metadata.

3. Use the resulting feature matrix as input to **`BAIT_Pipeline_v4_MultiArchitecture.ipynb`**.

---

## Dataset

Experiments use the **CERT Insider Threat Dataset r4.2**, developed by the Software Engineering Institute (SEI) at Carnegie Mellon University. It simulates the daily activities of 1,000 users over 17 months across five event sources: authentication, removable device usage, web browsing, email, and file operations. Ground-truth labels cover three main insider threat scenarios: data exfiltration, intellectual property theft, and system sabotage.

The preprocessed train/test splits (`4.2_meses_18.zip`) are included directly in this repository. The original raw logs can be obtained from the [CERT dataset page](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099).

Two complementary evaluation partitions are used throughout the pipeline:

- **Single-run audit** — the held-out CERT r4.2 test partition with 300 users, of whom 21 are malicious and 279 are normal (**7.00% malicious rate**). This partition is drawn directly from the original 1,000 CERT users and is never resampled.
- **Architecture-comparison protocol** — 30 stratified fold-level runs (`RepeatedStratifiedKFold`, 10 splits × 3 repeats) over a development pool of **951 profiles built exclusively from `X_train`** (`X_test` is never read by this step). Each fold splits the pool into a training subset of 855–856 profiles and a test subset of 95–96 profiles, both around 31.3–31.6% malicious.

The `X_train` development pool (951 profiles, ~31.5% malicious) is larger than a plain 700/300 split of the 1,000 original users, and its malicious prevalence is much higher than the 7.00% observed in the untouched single-run test set. The most likely explanation, based on the reconstructed sample counts (700 real training users + 251 SMOTE-generated malicious profiles = 951, with 300 malicious in total), is that `X_train.csv` already embeds SMOTE-balanced synthetic profiles from whichever script generated the preprocessed splits, rather than the raw, unbalanced training data. Section 1 of the notebook includes an `X_train`/`X_test` user-overlap check that reports empirically whether the two partitions share any users, once run against the real files.

---

## Notebook Structure

### `Extração de Features.ipynb` — Feature Engineering

| Step | Description |
|------|-------------|
| Device features | Parse `device.csv`; compute connect/disconnect counts, off-hours ratios, active days, unique PCs |
| Logon features | Parse `logon.csv`; compute session durations, logon/logoff ratios, missing logoff counts |
| File features | Parse `file.csv`; compute total/unique file accesses, PDF and executable file counts |
| Email features | Parse `email.csv`; compute attachment totals, unique BCC/To recipients, mean text length |
| HTTP features | Parse `http.csv`; compute total requests and unique URLs per user |
| Feature merging | Left-join all domain tables on `user`; fill missing values; apply domain prefix (`device_*`, `logon_*`, …) |
| Labeling | Assign binary labels (`1` = malicious, `0` = normal) from ground-truth metadata |

### `BAIT_Pipeline_v4_MultiArchitecture.ipynb` — Detection Pipeline

| # | Section | Purpose |
|---|---------|---------|
| 0 | Imports & Configuration | Global hyperparameters (seed, bins, ESS grid, fold counts, runtime repeats) |
| 1 | Data Loading | Load train/test CSVs; **new** `X_train`/`X_test` user-overlap check |
| 2 | Unified Metrics Module | Single source of truth for every reported metric (from the confusion matrix) |
| 3 | Preprocessing Pipeline | Discretization + latent (domain) nodes via K-Means, fit on train only |
| 4 | Bayesian Network Architectures | The 6 architectures + Chow-Liu / HillClimb-BIC structure learning |
| 5 | Threshold Calibration Toolkit | Youden's J is the single canonical criterion; Grid-F1, Platt, and Isotonic are diagnostic-only |
| 6 | Repeated Stratified K-Fold Evaluation | Architecture comparison, N = 30 paired folds, **`X_train` only** |
| 7 | Statistical Tests — Wilcoxon | Best architecture vs. every other, paired signed-rank test; **new** SIND-CL/SIND-HC structure-agreement diagnostic and auto-generated conclusion sentence |
| 8 | Estimator / Hyperparameter Selection | **New.** BDeu ESS selected on `Train2`/`Val` only, via validation AUPRC |
| 9 | Final Canonical Run | **`X_test` read here for the first time**; selected architecture, selected ESS, Youden's J threshold |
| 10 | SMOTE Ablation | Best architecture, with vs. without additional oversampling |
| 11 | Imbalance Sensitivity | Best architecture's performance as the malicious-class ratio is subsampled (1–30%) |
| 12 | CPT Stability via Bootstrap | Bootstrap resampling of CPT entries for the highest-MI nodes |
| 13 | ESS Sensitivity (post-hoc) | Held-out sensitivity check on `X_test` for the ESS values in the grid; **context only**, not a selection step |
| 14 | Runtime Analysis | Structure-learning, training, and inference time for all 6 architectures, **mean ± std over 7 repeated timings** |
| 15 | Final Architecture — Interpretability | CPD tables, **new** worked single-user example, and interpretive graph |
| 16 | Export All Results | File inventory |

---

## Reproducibility

All experiments use a fixed random seed (`RANDOM_STATE = 42`).

Key hyperparameters (from the pipeline configuration):
- `N_BINS = 8`, `STRATEGY = 'quantile'` (discretization)
- `N_LATENT_STATES = 3` (K-Means latent/domain node cardinality)
- `N_SPLITS_CV = 10`, `N_REPEATS_CV = 3` → 30 paired folds for the architecture comparison and the Wilcoxon test, drawn from `X_train` only
- `BN_PRIOR_TYPE = 'BDeu'`, `BN_ESS_DEFAULT = 5` (initial/coarse value used only to compare all six architectures in Section 6 on equal footing; overwritten in Section 8 by the value empirically selected on `Train2`/`Val`, ESS = 10 in the last validated run — every section from 9 onward uses the refined value)
- `ESS_GRID = [1, 5, 10, 20]` (candidates evaluated for selection in Section 8, and reused for the post-hoc sensitivity check in Section 13)
- `VAL_SIZE = 0.20` (validation-based threshold calibration and ESS selection)
- `THRESHOLD_CRITERION = 'f1'` — used only by the diagnostic-only Grid-F1 method in the Threshold Calibration Toolkit; it does not affect any reported table or figure, which all use Youden's J
- `IMBALANCE_RATIOS = [0.01, 0.02, 0.05, 0.10, 0.20, 0.30]` (Section 11 ablation)
- `N_RUNTIME_REPEATS = 7` (repeated timing measurements per architecture, Section 14; a single `time.time()` call was found to be noisy enough to make the runtime table and figure disagree in v3)
- `N_BOOTSTRAP = 1000` (95% CI on CV summary metrics), `N_BOOT_CPT = 100` (CPT-stability bootstrap)

---

## Citation

If you use BAIT in your research, please cite:

```bibtex
@article{santos2026bait,
  title     = {{BAIT}: {B}ayesian {A}rchitectures for {I}nterpretable {I}nsider {T}hreat {D}etection},
  author    = {Santos, Matheus V. P. dos and J{\'u}nior, Jos{\'e} Edson C. A. and
               Neto, Dami{\~a}o de O. M. and Liberal, Pedro H. G. and
               Morais, Anderson M. de and Lima, Milton and Campos, J. R. and
               Aires, Fernando and Santos, Wellison R. M.},
  journal   = {IEEE Access},
  year      = {2026},
  doi       = {10.1109/ACCESS.2024.0429000},
  note      = {Funded by EMBRAPII, Project CIS-AFCCT-2024-7-26-2}
}
```

---

## Acknowledgements

This work was supported by **EMBRAPII** through the project *Identificação e interpretação de desvios de comportamentos de usuários mal intencionados ou ligados ao cibercrime* (Project Code: CIS-AFCCT-2024-7-26-2), with financial resources from the PPI IoT/Manufatura 4.0 of the MCTI grant, signed with EMBRAPII. The Article Processing Charge was funded by CAPES (Coordenação de Aperfeiçoamento de Pessoal de Nível Superior; ROR: 00x0ma614).

Affiliations:
- **CISSA / CESAR School** — Centro Integrado de Segurança em Sistemas Avançados, Recife, Pernambuco, Brazil
- **CISUC / University of Coimbra** — Centre for Informatics and Systems of the University of Coimbra, Portugal
- **UFRPE** — Universidade Federal Rural de Pernambuco, Recife, Brazil

---

## Data and Code Availability

Source code and experimental artifacts are available at [https://github.com/CESAR-CISSA/SIND](https://github.com/CESAR-CISSA/SIND). The repository name is retained for continuity with the existing public codebase and hosts the updated BAIT architecture-comparison code and artifacts.

---

## License

This repository is released for research and academic use. Please refer to [LICENSE](LICENSE) for details.
