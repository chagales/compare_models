# LLM Vulnerability Detection

Evaluation of Large Language Models for CVE/CWE vulnerability detection in source code.

## Overview

This repository contains the code and data for evaluating 8 LLMs across 5 programming languages for vulnerability detection tasks. The study compares general-purpose models against code-specialized models.

## Models Evaluated

| Model | Type | Parameters | Ollama Identifier |
|-------|------|------------|-------------------|
| Llama3 | General-purpose | 8B | `llama3:8b-instruct-q4_0` |
| Gemma2 | General-purpose | 9B | `gemma2:9b-instruct-q4_0` |
| Mistral | General-purpose | 7B | `mistral:7b-instruct-v0.3-q4_0` |
| Qwen3 | General-purpose | 30B | `qwen3:30b` |
| CodeLlama | Code-specialized | 13B | `codellama:13b-instruct-q4_0` |
| CodeGemma | Code-specialized | 7B | `codegemma:7b-instruct-q4_0` |
| DeepSeek-Coder | Code-specialized | 6.7B | `deepseek-coder:6.7b-instruct-q4_0` |
| Qwen3-Coder | Code-specialized | 30B | `qwen3-coder:30b` |

## Languages

C/C++, Go, Java, Python, Ruby (100 samples each, 500 total)

## Requirements

- Python 3.10+
- [Ollama](https://ollama.ai/) v0.1.27+
- GPU with 40GB+ VRAM (tested on NVIDIA A100)
- CUDA 12.2+

### Python Dependencies

```bash
pip install pandas openpyxl requests tqdm matplotlib seaborn
```

## Configuration Parameters

### Inference Parameters

| Parameter | Value |
|-----------|-------|
| temperature | 0.1 |
| max_tokens | 2048 |
| top_p | 0.95 |
| top_k | 40 |
| repeat_penalty | 1.1 |
| seed | 42 |

## Usage

### 1. Setup Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull models
ollama pull llama3:8b-instruct-q4_0
ollama pull gemma2:9b-instruct-q4_0
ollama pull mistral:7b-instruct-v0.3-q4_0
ollama pull codellama:13b-instruct-q4_0
ollama pull codegemma:7b-instruct-q4_0
ollama pull deepseek-coder:6.7b-instruct-q4_0
ollama pull qwen3:30b
ollama pull qwen3-coder:30b
```

### 2. Run Experiments

Open the Jupyter notebook in Google Colab or locally:

```bash
jupyter notebook src/LLM_Vulnerability_Detection_REVISED.ipynb
```

### 3. Analyze Results

```bash
# Full analysis of all results
python scripts/analyze_all_complete_results.py

# REIN metrics analysis
python scripts/analyze_relevant_information_metrics.py
```

## Repository Structure

```
repo/
├── README.md
├── src/
│   └── LLM_Vulnerability_Detection_REVISED.ipynb  # Main experiment notebook
├── scripts/
│   ├── analyze_all_complete_results.py            # Detection metrics analysis
│   └── analyze_relevant_information_metrics.py    # REIN metrics analysis
└── results/
    ├── figures/
    │   ├── figure1_cwe_precision.png
    │   ├── figure2_cwe_recall.png
    │   └── figure3_heatmap.png
    ├── complete_analysis_results.csv              # All metrics for 40 combinations
    ├── cwe_f1_pivot_table.csv                     # F1-Score by model/language
    ├── cwe_reinf1_pivot_table.csv                 # REINF1 by model/language
    ├── rein_metrics_summary_all_models.csv        # REIN metrics summary
    └── *_sampled_100_seed42.csv                   # Sampled datasets per language
```

## Key Results

| Metric | Best Model | Score |
|--------|------------|-------|
| CWE F1-Score (avg) | Llama3 | 13.01% |
| CWE REINF1 (avg) | Llama3 | 56.58% |
| CVE Detection | All models | 0.00% |

**Main findings:**
- General-purpose Llama3 outperforms all code-specialized models
- CVE detection failed completely across all models
- Ruby/Python show best results; C shows lowest performance

## Dataset

Based on [CVEfixes](https://github.com/secureIT-project/CVEfixes) dataset with stratified random sampling (seed=42).

## Citation

```bibtex
@article{vulnerability_detection_llm_2025,
  title={Analysis of the Precision of LLM Code Generation for Vulnerability Detection},
  author={[Federico Muñoz-Babianoa, Paula Lamo and Ricardo S. Alonso ]},
  journal={[Journal]},
  year={2025}
}
```

## License

[Specify license]
