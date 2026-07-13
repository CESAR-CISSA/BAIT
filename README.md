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
- Optional **SMOTE** class balancing, evaluated explicitly as an ablation rather than assumed by default
- **MAP estimation with a BDeu prior** for parameter learning
- **Validation-based threshold calibration**

The winning architecture is selected empirically (not fixed a priori) through a 30-run repeated stratified cross-validation comparison, giving security analysts an auditable, interpretable evidence path — the graph structure, the CPTs, and the posterior risk score — behind every alert.

---

## Evaluated Bayesian Architectures

BAIT compares six architectures, built from the same preprocessed (discretized + latent) feature set:

| Key | Architecture | Description |
|-----|--------------|-------------|
| NB | Naive Bayes | Label → every feature; features conditionally independent given the class. Classical baseline. |
| SNBN | Semi-Naive Bayesian Network | Naive Bayes backbone plus a fixed intra-domain feature chain (manually defined local dependencies). |
| HL | Hierarchical Latent (fixed) | Label → latent domain node (K-Means summary) → domain features; no learned structure among latents. |
| **TAN-F** | **TAN over Features (Chow-Liu)** | Label → every feature, plus a Chow-Liu maximum-mutual-information spanning tree learned directly among the *observed* behavioral features (Tree-Augmented Naive Bayes). |
| SNBN-CL | SNBN + Latent Structure (Chow-Liu) | Latent/domain-level dependencies learned with the Chow-Liu algorithm. |
| SNBN-HC | SNBN + Latent Structure (HillClimb-BIC) | Latent/domain-level dependencies learned via greedy hill-climbing search scored with BIC. |

**TAN-F (TAN over Features, learned with Chow-Liu) was selected as the best overall architecture** across the 30-fold repeated cross-validation comparison, and is the architecture reported for the single-run auditable evaluation.

---

## Key Results (CERT r4.2)

### 30-run repeated stratified cross-validation (primary architecture-selection evidence)

| Architecture | Edges | Acc. | Precision | Recall | F1 | FPR | AUPRC |
|---|---|---|---|---|---|---|---|
| Naive Bayes | 24 | 0.9536 ± 0.0204 | 0.8740 ± 0.0639 | 0.9657 ± 0.0373 | 0.9155 ± 0.0344 | 0.0506 ± 0.0294 | 0.9744 ± 0.0168 |
| SNBN | 43 | 0.9819 ± 0.0133 | 0.9514 ± 0.0380 | **0.9815 ± 0.0323** | 0.9655 ± 0.0253 | 0.0179 ± 0.0148 | 0.9938 ± 0.0072 |
| Hierarchical Latent (fixed) | 28 | 0.9262 ± 0.0159 | 0.8423 ± 0.0505 | 0.8838 ± 0.0626 | 0.8598 ± 0.0302 | 0.0591 ± 0.0249 | 0.9070 ± 0.0468 |
| **TAN-F** | 47 | **0.9864 ± 0.0103** | **0.9694 ± 0.0294** | 0.9794 ± 0.0349 | **0.9736 ± 0.0203** | **0.0111 ± 0.0109** | **0.9957 ± 0.0053** |
| SNBN + Latent (Chow-Liu) | 31 | 0.9361 ± 0.0243 | 0.8347 ± 0.0729 | 0.9503 ± 0.0564 | 0.8853 ± 0.0399 | 0.0688 ± 0.0369 | 0.9615 ± 0.0231 |
| SNBN + Latent (HillClimb/BIC) | 31 | 0.9361 ± 0.0243 | 0.8347 ± 0.0729 | 0.9503 ± 0.0564 | 0.8853 ± 0.0399 | 0.0688 ± 0.0369 | 0.9615 ± 0.0231 |

Paired Wilcoxon signed-rank tests show TAN-F is significantly better than Naive Bayes, the fixed hierarchical latent architecture, and both latent-structure variants (p < 0.0001); the comparison against SNBN is directionally favorable but not statistically significant at the 0.05 level (p = 0.0825).

### Single held-out run — selected architecture (TAN-F)

Evaluated on a strictly imbalanced held-out test set (279 normal / 21 malicious, 7.00% malicious rate) to reflect a realistic needle-in-a-haystack scenario.

| TP | FP | TN | FN | Threshold | Acc. | Precision | Recall | F1 | FPR | AUC-ROC | AUPRC |
|----|----|----|----|-----------|------|-----------|--------|----|----|---------|--------|
| 20 | 1 | 278 | 1 | 0.73 | 0.9933 | 0.9524 | 0.9524 | 0.9524 | 0.0036 | 0.9991 | 0.9901 |

---

## Architecture

BAIT operates as an end-to-end, six-stage pipeline:

`Raw Activity Logs → Feature Engineering → MI Feature Selection → Train-Fitted Discretization → Bayesian Architecture → Threshold Calibration → Classification`

1. **Feature Engineering** — raw event streams (authentication, device, e-mail, file, Web) are aggregated into user-level behavioral profiles.
2. **MI Feature Selection** — Mutual Information ranks candidate variables and retains a compact 24-feature subset.
3. **Train-Fitted Discretization** — continuous features are binned using boundaries fit only on the training partition (no test leakage).
4. **Optional SMOTE** — synthetic oversampling of the training subset, evaluated as an explicit ablation rather than a default assumption.
5. **Bayesian Architecture** — one of six architectures (see above) is trained via MAP estimation with a BDeu prior.
6. **Threshold Calibration & Classification** — posterior probabilities `P(Label = 1 | evidence)` are converted into binary alerts using a validation-selected threshold.

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
├── BAIT_Pipeline_v3_MultiArchitecture.ipynb    # Step 2 — architecture comparison, calibration & final evaluation
├── 4.2_meses_18.zip                            # Preprocessed CERT r4.2 splits (output of Step 1)
│   ├── X_train.csv
│   ├── X_test.csv
│   ├── y_train.csv
│   └── y_test.csv
└── README.md
```

The two notebooks form a sequential pipeline: **`Extração de Features`** processes the raw CERT r4.2 CSV logs into a per-user behavioral feature matrix, and **`BAIT_Pipeline_v3_MultiArchitecture`** consumes that matrix to build, train, calibrate, and compare all six Bayesian architectures, selecting the best one and reproducing every table and figure reported in the manuscript.

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
   jupyter notebook "BAIT_Pipeline_v3_MultiArchitecture.ipynb"
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

3. Use the resulting feature matrix as input to **`BAIT_Pipeline_v3_MultiArchitecture.ipynb`**.

---

## Dataset

Experiments use the **CERT Insider Threat Dataset r4.2**, developed by the Software Engineering Institute (SEI) at Carnegie Mellon University. It simulates the daily activities of 1,000 users over 17 months across five event sources: authentication, removable device usage, web browsing, email, and file operations. Ground-truth labels cover three main insider threat scenarios: data exfiltration, intellectual property theft, and system sabotage.

The preprocessed train/test splits (`4.2_meses_18.zip`) are included directly in this repository. The original raw logs can be obtained from the [CERT dataset page](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099).

Two complementary evaluation partitions are used throughout the pipeline:

- **Single-run audit** — the held-out CERT r4.2 test partition with 300 users, of whom 21 are malicious and 279 are normal (**7.00% malicious rate**).
- **Architecture-comparison protocol** — 30 stratified fold-level runs (`RepeatedStratifiedKFold`, 10 splits × 3 repeats) over the pooled train+test artifact (1,251 profiles), where each test fold contains 125–126 profiles (25.60–26.19% malicious) and each training fold contains 1,125–1,126 profiles (25.60–25.67% malicious).

Because the raw pre-split CSVs exhibit a class-imbalance mismatch between train (~31.5% malicious) and test (~7.0% malicious) — consistent with a temporal split where earlier logged periods contain a denser concentration of malicious activity — the architecture comparison pools and re-splits the data to avoid conflating this mismatch with genuine architecture differences, while the single-run audit intentionally preserves the harder, more realistic imbalanced test distribution.

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

### `BAIT_Pipeline_v3_MultiArchitecture.ipynb` — Detection Pipeline

| # | Section | Purpose |
|---|---------|---------|
| 0 | Imports & Configuration | Global hyperparameters (seed, bins, ESS, fold counts, threshold grid) |
| 1 | Data Loading | Load train/test CSVs, select top-24 features, report train/test class-balance mismatch |
| 2 | Unified Metrics Module | Single source of truth for every reported metric (from the confusion matrix) |
| 3 | Preprocessing Pipeline | Discretization + latent (domain) nodes via K-Means, fit on train only |
| 4 | Bayesian Network Architectures | The 6 architectures + Chow-Liu / HillClimb-BIC structure learning |
| 5 | Threshold Calibration Toolkit | 4 threshold-selection strategies (Grid-F1, Youden's J, Platt, Isotonic) |
| 6 | Repeated Stratified K-Fold Evaluation | Architecture comparison, N = 30 paired folds |
| 7 | Statistical Tests — Wilcoxon | Best architecture vs. every other, paired signed-rank test |
| 8 | Best-Architecture Selection & Final Run | Canonical Train2/Val/Test evaluation of the winning architecture |
| 9 | SMOTE Ablation | Best architecture with vs. without synthetic oversampling |
| 10 | Imbalance Sensitivity | Best architecture's performance as the malicious-class ratio is subsampled (1–30%) |
| 11 | CPT Stability via Bootstrap | Bootstrap resampling of CPT entries for the highest-MI nodes |
| 12 | MAP vs. MLE Analysis | Estimator sensitivity across BDeu equivalent sample sizes |
| 13 | Runtime Analysis | Structure-learning, training, and inference time for all 6 architectures |
| 14 | CPD Tables & Interpretability Graph | Mutual-Information ranking, CPD tables, node-size-proportional influence graph |
| 15 | Output Inventory | Full listing of exported tables and figures |

---

## Reproducibility

All experiments use a fixed random seed (`RANDOM_STATE = 42`).

Key hyperparameters (from the pipeline configuration):
- `N_BINS = 8`, `STRATEGY = 'quantile'` (discretization)
- `N_LATENT_STATES = 3` (K-Means latent/domain node cardinality)
- `N_SPLITS_CV = 10`, `N_REPEATS_CV = 3` → 30 paired folds for the architecture comparison and the Wilcoxon test
- `BN_PRIOR_TYPE = 'BDeu'`, `BN_ESS_DEFAULT = 5` (MAP estimation)
- `VAL_SIZE = 0.20`, `THRESHOLD_CRITERION = 'f1'` (validation-based threshold calibration)
- `IMBALANCE_RATIOS = [0.01, 0.02, 0.05, 0.10, 0.20, 0.30]` (Section 10 ablation)
- `ESS_GRID = [1, 5, 10, 20]` (Section 12 estimator-sensitivity ablation)
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
