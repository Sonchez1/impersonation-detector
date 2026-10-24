# Changelog

## 0.4.0 — 2026-10-23

Public example brand, two options ported back from the browser extension, Layer 2 retrained.

- **Example brand.** Every example, the benchmark's default protected set, the CI job, the
  paper and the Internet-Draft now use LinkedIn (`linkedin.com`), a public brand that is a
  common impersonation target; the previous example brand is gone from code, tests, corpora,
  benchmark outputs and documentation. The seed corpus was already brand-parametric; its one
  hard-coded item, the punycode credential phish `c08`, is now templated from the protected
  domain (`{domain_punycode}`, the IDNA form with one Cyrillic confusable). The three
  paraphrased corpora (`paraphrase_llama3.1_8b.jsonl`, `heldout_gemma3_27b.jsonl`,
  `heldout2_gemma3_27b.jsonl`) were re-branded by token substitution, so they are the same
  rewrites with the new brand, and every benchmark was re-run.
- **Layer 2 retrained.** The training brand list swaps the old example brand for Glassdoor;
  the university-office negative family no longer carries a hard-coded brand-named admin
  entry. New weights (`scorer_weights.json`, bias −2.75); holdout precision 1.000 / recall
  0.970 / F1 0.985 / AUC 0.992 (0.3.0: 1.000 / 0.973 / 0.987 / 0.995). The 99th percentile of
  Layer 2's score on 3,200 synthetic benign senders is 0.163 (was 0.151), still under the
  0.20 evidence floor.
- **Two options from real mail**, found while testing the TypeScript port
  ([impersonation-guard](https://github.com/Sonchez1/impersonation-guard)) on Gmail.
  Both default to off so verdicts are identical to 0.3.0.
  `Detector(skip_protected_subdomains=True)`: a sender or link host that is a subdomain of a
  protected domain (`e.linkedin.com` for `linkedin.com`) is the genuine domain, never a Layer 1
  lookalike of it (`e.linkedin.com` is edit distance 2 from `linkedin.com` and was flagged).
  `Detector(brand_on_own_domain_is_benign=True)`: the brand's own name in the display name or
  local part of an address on a protected domain (`linkedin@e.linkedin.com`) is the sender, not
  a brand claim, so the four brand-claim features are zero for it.
- **Domain watch.** `benchmarks/watch_linkedin.json` (2026-10-23) replaces the old scan: 211
  candidates, 118 live, 81 with MX, 16 at a brand-protection registrar.
- **Results.** Rule backend: every cell identical to 0.3.0 on the seed corpus (all ten
  variants), both development corpora and the frozen held-out corpus; the ablation is
  identical. LLM backends (all re-run uncached, recall 1.00 and hijack 0 everywhere): Llama 3.1 8B
  full-pipeline FPR 0.07 on seed clean and the Llama-paraphrased corpus (was 0.03), 0.07 on
  Gemma #1 (unchanged), 0.13 on the frozen corpus (was 0.10; b18 is the new hold); Gemma 3 27B
  0.00 on seed and the Llama-paraphrased corpus (unchanged), 0.03 on Gemma #1 (was 0.00) and
  0.07 on the frozen corpus (was 0.03), both from the password-changed notice b17 that it now
  reads as a credential ask. Part of the movement is the brand itself: both models read "Sign
  in to linkedin.com" as an off-platform move. Uncached p50 3.2–3.7 s (8B), 17–19 s (27B).
- 82 tests.

## 0.3.0 — 2026-10-15

Layer 2 → Layer 3 fusion, and the closing of every gap the benchmark could show.

- **Fusion.** The pipeline computes structured sender facts from Layers 1–2 (platform-owned,
  institutional, free-webmail, lookalike, or unrelated sender domain; display name claims
  the brand; link hosts platform-only / off-platform / same-as-sender / lookalike /
  embedded-domain) and hands them to both Layer 3 classifiers. The LLM prompt carries the
  platform policy; the rule classifier uses the facts directly. A deterministic discount
  then applies to an impersonation verdict when the sender is a verified institution, an
  organisation on its own domain that Layer 2 finds unremarkable, or a webmail peer, *and*
  nothing sensitive is asked for, *and* links go nowhere the sender does not control, *and*
  the body does not claim the platform's authority. "Nothing sensitive" is vetoed by three
  sources: the cue detector over de-obfuscated views, the model's label when it is an ask
  type, and, for verified senders only, the model's own signals (a verified sender whose
  message the model reads as asking for a code is held, never waved through).
- **Evidence floor.** Risk components below `Thresholds.noise_floor` (0.20, above the 99th
  percentile of Layer 2's score on 3,200 synthetic benign senders, 0.151) do not combine.
- **New Layer 2 features.** Brand-agnostic embedded domain (`orbitallabs.io.docs-share.site`,
  weight +5.65) and lure-worded throwaway domains (`hr-portal.co`, `auth-check.top`,
  `secure-portal.app`, weight +5.12); both synth-trained. Layer 1 floor when a link embeds
  the sender's own domain.
- **Cues.** 1→i leet view; rn→m / vv→w ASCII-confusable view; "log on"; N-digit codes
  with "respond with"; prepaid and branded cards; "$600 weekly"; "purchase the initial kit";
  BEC pretexts; "verify it"; conditional threats ("if you don't verify") are not negated
  requests; negation window widened to the clause. Host extraction strips zero-width
  characters before matching.
- **Benchmark.** Body-text variants leave URLs and bare domains untouched. The paraphrase
  generator strips "Here is the rewritten message:" preambles, retries refusals with a second
  prompt, drops the rest, and takes `--style` to produce distinct held-out corpora.
  Persistent LLM cache; `--only-extra`; `--dump`.
- **Results** (full pipeline, recall / FPR): rule 1.00 / 0.00 on all ten seed variants, the
  Llama-paraphrased corpus, and the first Gemma-paraphrased corpus; Gemma 3 27B the same;
  Llama 3.1 8B recall 1.00 everywhere with FPR 0.03–0.07, every false positive a genuine
  notice the model insists asks for credentials. A second Gemma-paraphrased corpus in a
  different register was evaluated once after all changes; see README.
- 80 tests.

## 0.2.0 — 2026-10-13

The other two legs of the endeavor, same approach as the message detector.

- **Lookalike-domain watch** (`domainwatch.py`): 13-technique permutation generator,
  pluggable resolver (system DNS, `dig` MX, public RDAP registration date), Layer 2
  scoring plus live / recently-registered / mail-capable evidence, JSON export, and a
  `blocklist=` parameter on `Detector` that blocks senders and links on judged domains.
  CLI `watch`, `analyze --blocklist`.
- **Account-takeover detector** (`ato.py`): per-account baseline, 15 named features,
  verdicts with reasons at every login and sensitive change; `CampaignDetector` for
  shared-IP credential stuffing across accounts, feeding `attacker_ips` back into the
  per-account scorer. Synthetic benchmark with 9 benign day types and 8 attack scripts
  (`ato_bench.py`, CLI `ato-bench`); CLI `ato` for JSONL event logs.
- Publishing: `publish.yml` releases to PyPI on a `v*` tag via Trusted Publishing.
- 61 tests.

## 0.1.0 — 2026-10-09

First complete release of all four layers.

- **Layer 1** (from 0.0.1): UTS #39 confusable skeletons, mixed-script detection,
  Damerau–Levenshtein typo distance, punycode decoding. New: `fold_skeleton` so
  confusables with upper-case prototypes (`0` → `O`) match case-insensitively.
- **Layer 2**: explainable logistic-regression sender scorer over 21 named features
  (lookalike domain, brand-in-subdomain, affix/prefix, TLD swap, leet, free-mail with
  brand display name, invisible characters, role words). Pure Python; weights shipped;
  retrain with `python -m impersonation_detector.train`. Holdout F1 0.99 on synthetic
  senders across 8 brands.
- **Layer 3**: message-intent classification (support impersonation, recruiter scam,
  credential phish, payment redirect). Rule baseline with request-verb and negation-aware
  cues, confusable folding, leet and letter-spacing de-obfuscation. LLM classifier with
  Ollama / OpenAI-compatible / Anthropic backends, nonce-delimited untrusted input,
  independent injection pre-filter, schema validation, fail-closed `unknown`.
- **Pipeline**: noisy-OR risk with Layer 1 and injection floors; allow / warn / hold /
  block; `Middleware.wrap` for send pipelines; JSON output.
- **Layer 4**: 76-message brand-parametric seed corpus, 10 label-preserving adversarial
  variants, per-layer recall / FPR / per-class recall / injection hijack rate / latency.
  `impersonation-detector bench` writes JSON and Markdown reports.
- CLI: `check`, `score`, `analyze`, `bench`, `export-seed`, `skeleton`.

## 0.0.1 — 2026-10-01

- Layer 1 only.
