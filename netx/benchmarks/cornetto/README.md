# Cornetto Benchmark

Cornetto is a benchmark for evaluating LLM-driven network configuration repair. Given a set of faulty router configurations and a formal specification of correct network behaviour (written as a set of data-plane predicates), a model must produce a corrected configuration. Correctness is verified with [Batfish](https://www.batfish.org/).

The benchmark supports four pipeline modes — zero-shot, repair (retry on failure), retrieval-augmented, and fully agentic — and covers 231 misconfiguration scenarios on topologies with 20 to 754 nodes.

---

## Installation

```bash
git clone https://github.com/iprotogeros/cornetto-repo.git
cd cornetto-repo
```

And install dependencies and libraries:
```bash
conda create -n net python=3.12
conda activate net
pip install -r requirements.txt
```

> **Note**: `vllm` requires a CUDA-capable GPU. If you are using API-only providers (OpenAI, Anthropic, Google, Mistral) you can omit it. `pip install -e .` will still succeed — vllm is not in the required dependencies.

> **Editable install required**: the `cornetto` CLI entry point and `python -m src.benchmark.zero_shot` both resolve configs relative to the repo root, so always run from within the cloned directory.

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env   # then edit .env
```

```
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
GOOGLE_API_KEY=...
MISTRAL_API_KEY=...
```

You also need a running Batfish server. Cornetto uses a **customised Batfish container** to export forwarding decisions by router and destination prefix. Its evaluator builds per-prefix forwarding graphs and applies Config2Spec algorithms to extract predicates. The standard `batfish/batfish` image does not provide the custom forwarding table. [Forwarding table adapter](src/utils/evaluation_utils/forwarding_analysis/get_forwarding_behaviour_table.py)

Pull and start the container with the provided script:

```bash
bash scripts/batfish_setup/pull_and_run_container.sh
```

This stops any existing container named `batfish`, pulls `iprotogeros/batfish-allione:forwarding-analysis-0.1`, and starts it on port 9996.

---

## Dataset

The dataset contains faulty router configurations, forwarding specifications, and network topology. This checkout includes all 231 scenarios under `cornetto-benchmark/main_dataset/`. [Public dataset on Hugging Face](https://huggingface.co/datasets/iprotogeros/cornetto-benchmark)

Download the dataset once after cloning:

```bash
python download_dataset.py
```

This saves the dataset to `dataset/main_dataset/`. The script accepts `--token` for private access and `--local-dir` to change the destination.

> **Features that require ground truth**: The LLM-as-judge diagnosis scorer (`diagnosis_judge.enabled: True`) compares model outputs against `fault_metrics.csv`, and the `oracle` / `random_with_oracle` context-sampling modes use the correct (`initial`) configurations. These artifacts are not part of the public dataset.

---

## Quickstart

```bash
# Zero-shot inference with gpt-5.4-mini (public dataset, all scenarios)
cornetto model.provider=openai model.model_name=gpt-5.4-mini-2026-03-17

# Agentic pipeline with Claude (public dataset)
cornetto --config-name agent_config \
         model.provider=anthropic \
         model.model_name=claude-opus-4-5-20251101

# Private evaluation on scenario-003 with oracle context and LLM-as-judge
# (requires ground-truth artifacts — see Dataset section)
cornetto --config-name private_eval model.provider=openai model.model_name=gpt-5.4-mini-2026-03-17
```

`cornetto` is equivalent to `python -m src.benchmark.zero_shot`. Results are written to `results_main/` (path printed at startup).

Three configs are provided in `configs/`:

| Config | Use case |
|---|---|
| `zero_shot.yaml` | Default — public dataset, all pipeline modes except `agentic` |
| `agent_config.yaml` | Agentic pipeline (`pipeline_mode: agentic`) |
| `private_eval.yaml` | Full evaluation on `scenario-003` with oracle context and LLM-as-judge (requires ground-truth artifacts) |

---

## Pipeline modes

Set `pipeline_mode` in the config or on the command line:

| Mode | Description |
|---|---|
| `naive` | Single-pass zero-shot generation |
| `repair` | Retry on verification failure (can warm-start from a previous naive run) |
| `retrieval` | Retrieval-augmented generation |
| `agentic` | Fully agentic loop with tool access (Batfish verification, config inspection) |

`naive`, `repair`, and `retrieval` use `configs/zero_shot.yaml`. `agentic` uses `configs/agent_config.yaml`.

---

## Configuration reference

### Model

| Key | Default | Description |
|---|---|---|
| `model.provider` | `zai` | API provider: `openai`, `anthropic`, `google`, `mistral`, `hf`, `ollama` |
| `model.model_name` | `glm-4.7` | Model identifier as expected by the provider |
| `model.max_tokens` | `40000` | Maximum output tokens |
| `model.temperature` | `1.0` | Sampling temperature |
| `model.context_sampling` | `random` | Which router configs to include: `random` (default), `oracle` / `random_with_oracle` (require `initial_configs` — not in public dataset) |
| `model.max_context_tokens` | `full` | Token budget for configs in the prompt (`full` or integer) |
| `model.batch_api` | `False` | Use batch API (OpenAI/Anthropic) for offline jobs |
| `model.few_shot_mode` | `False` | Enable few-shot examples in the prompt |

### Agentic-specific

| Key | Default | Description |
|---|---|---|
| `agentic.max_steps` | `30` | Maximum tool-call steps per scenario |
| `agentic.verification_mode` | `per_step` | When to run Batfish: `per_step` or `post_hoc` |
| `agentic.context_prefill` | `True` | Pre-populate agent context with network summary |

### Repair-specific

| Key | Description |
|---|---|
| `naive_results_dir` | Path to a prior naive run; successful tasks are skipped |
| `naive_success_threshold` | Score threshold for considering a prior result successful (default `1.0`) |
| `naive_retry_parse_failures` | Re-run tasks that had parse errors (default `true`) |

### LLM-as-judge diagnosis scoring

When `diagnosis_judge.enabled: True`, a panel of LLM judges scores the model's fault diagnosis against the ground truth in `fault_metrics.csv`. **This feature requires ground-truth artifacts not included in the public dataset.** Set `diagnosis_judge.enabled: False` (or omit it) when running against the public dataset.

### HuggingFace / vLLM

Set `model.use_vllm: True` and `model.num_gpus: N` to serve a HuggingFace model locally via vLLM.

---

## Dataset format

After downloading, each scenario lives in `dataset/main_dataset/scenario-NNN/`. The public dataset includes only the artifacts needed to run the benchmark without leaking the ground-truth repair:

```
scenario-NNN/
├── final_configs/configs/    # faulty router configs (.cfg) presented to the model
├── specifications/
│   └── specifications_*.csv  # Batfish predicates at multiple sampling rates
└── data_and_metrics/
    └── topology.json         # network graph
```

The private evaluation example requires additional artifacts for `scenario-003`, including `initial_configs/` and `data_and_metrics/fault_metrics.csv`.

The specifications CSV compares the golden and faulty configurations. A repair should preserve `intact` predicates, restore `broken_removed` predicates, and eliminate `broken_added` predicates. [Dataset construction and CSV format](cornetto-benchmark/README.md)

> **Public dataset limitations**: `oracle` and `random_with_oracle` context-sampling require `initial_configs/` (correct configurations), and the LLM-as-judge scorer requires `fault_metrics.csv`. Neither is included in the public dataset. Use `context_sampling: random` and `diagnosis_judge.enabled: False` when running against the public dataset.

---

## Citation

If you use Cornetto in your research, please cite:

```bibtex
@misc{protogeros2026benchmarkingllmdrivennetworkconfiguration,
      title={Benchmarking LLM-Driven Network Configuration Repair}, 
      author={Ioannis Protogeros and Rufat Asadli and Benjamin Hoffman and Laurent Vanbever},
      year={2026},
      eprint={2604.22513},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://arxiv.org/abs/2604.22513}, 
}
```
