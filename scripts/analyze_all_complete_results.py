"""
Complete Analysis of ALL Results from Colab Execution
8 Models x 5 Languages = 40 combinations
"""
import pandas as pd
import re
import ast
import os
from pathlib import Path

# Configuration
RESULTS_DIR = 'resultados'

# IMPROVED EXTRACTION FUNCTIONS
def extract_cve_codes(text):
    if pd.isna(text) or text == "ERROR" or text == "":
        return []
    text = str(text)
    pattern = r'CVE-(\d{4})-(\d{4,7})'
    matches = re.findall(pattern, text, re.IGNORECASE)
    cve_codes = [f'CVE-{year}-{cve_id}' for year, cve_id in matches]
    seen = set()
    unique_codes = []
    for code in cve_codes:
        code_upper = code.upper()
        if code_upper not in seen:
            seen.add(code_upper)
            unique_codes.append(code_upper)
    return unique_codes

def extract_cwe_codes(text):
    if pd.isna(text) or text == "ERROR" or text == "":
        return []
    text = str(text)
    pattern = r'CWE-(\d{1,4})'
    matches = re.findall(pattern, text, re.IGNORECASE)
    cwe_codes = [f'CWE-{cwe_id}' for cwe_id in matches]
    seen = set()
    unique_codes = []
    for code in cwe_codes:
        code_upper = code.upper()
        if code_upper not in seen:
            seen.add(code_upper)
            unique_codes.append(code_upper)
    return unique_codes

def parse_ground_truth(value):
    if pd.isna(value) or value == "" or value is None:
        return []
    if isinstance(value, list):
        return value
    value_str = str(value)
    try:
        parsed = ast.literal_eval(value_str)
        if isinstance(parsed, list):
            return parsed
        else:
            return [str(parsed)]
    except (ValueError, SyntaxError):
        return [value_str] if value_str else []

def calculate_detection_metrics(predicted_list, ground_truth_list):
    """Calculate precision, recall, F1 for code detection."""
    tp = fp = fn = 0
    for pred, gt in zip(predicted_list, ground_truth_list):
        pred_set = set(pred) if pred else set()
        gt_set = set(gt) if gt else set()
        tp += len(pred_set & gt_set)
        fp += len(pred_set - gt_set)
        fn += len(gt_set - pred_set)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {'precision': precision, 'recall': recall, 'f1': f1, 'tp': tp, 'fp': fp, 'fn': fn}

def classify_response_quality(predicted, ground_truth, response_text):
    """Classify response for REIN metrics."""
    pred_set = set(predicted) if predicted else set()
    gt_set = set(ground_truth) if ground_truth else set()

    if pd.isna(response_text) or response_text == "ERROR" or str(response_text).strip() == "":
        return 'missing'
    if not pred_set:
        if len(str(response_text)) > 50:
            return 'irrelevant'
        else:
            return 'missing'
    if pred_set & gt_set:
        return 'useful'
    else:
        return 'irrelevant'

def calculate_rein_metrics(classifications):
    """Calculate REIN metrics from classifications."""
    ui = classifications.count('useful')
    ni = classifications.count('irrelevant')
    mi = classifications.count('missing')

    reinp = ui / (ui + ni) if (ui + ni) > 0 else 0.0
    reinr = ui / (ui + mi) if (ui + mi) > 0 else 0.0
    reinf1 = 2 * (reinp * reinr) / (reinp + reinr) if (reinp + reinr) > 0 else 0.0
    rein_rate = ni / (ui + ni) if (ui + ni) > 0 else 0.0
    rein_fn_rate = mi / (ui + mi) if (ui + mi) > 0 else 0.0

    return {
        'ui': ui, 'ni': ni, 'mi': mi,
        'reinp': reinp, 'reinr': reinr, 'reinf1': reinf1,
        'rein_rate': rein_rate, 'rein_fn_rate': rein_fn_rate
    }

def get_model_key(model_name):
    """Get standardized model key for column names."""
    model_map = {
        'llama3': 'llama3',
        'gemma2': 'gemma2',
        'mistral': 'mistral',
        'codegemma': 'codegemma',
        'codellama': 'codellama',
        'deepseek': 'deepseek',
        'qwen3': 'qwen3',
        'qwen3-coder': 'qwen3-coder'
    }
    return model_map.get(model_name.lower(), model_name.lower())

def analyze_file(filepath):
    """Analyze a single results file."""
    filename = os.path.basename(filepath)

    # Parse filename to get model and language
    # Format: model_language_results_YYYYMMDD_HHMMSS.csv
    parts = filename.replace('_results_', '_').split('_')
    model_name = parts[0]
    language = parts[1]

    # Handle special case for qwen3-coder
    if model_name == 'qwen3' and len(parts) > 2 and parts[1] == 'coder':
        model_name = 'qwen3-coder'
        language = parts[2]

    # Load file
    try:
        if filepath.endswith('.xlsx'):
            df = pd.read_excel(filepath)
        else:
            df = pd.read_csv(filepath)
    except Exception as e:
        print(f"  Error loading {filename}: {e}")
        return None

    if len(df) == 0:
        return None

    # Find response columns
    model_key = get_model_key(model_name)
    cve_col = None
    cwe_col = None

    for col in df.columns:
        col_lower = col.lower()
        if 'cve' in col_lower and 'response' in col_lower:
            cve_col = col
        if 'cwe' in col_lower and 'response' in col_lower:
            cwe_col = col

    if not cve_col or not cwe_col:
        print(f"  Warning: Missing response columns in {filename}")
        return None

    # Apply extraction
    df['cve_extracted'] = df[cve_col].apply(extract_cve_codes)
    df['cwe_extracted'] = df[cwe_col].apply(extract_cwe_codes)

    # Parse ground truth
    df['gt_cve'] = df['cve_id'].apply(parse_ground_truth)
    df['gt_cwe'] = df['cwe_id'].apply(parse_ground_truth)

    # Calculate detection metrics
    cve_metrics = calculate_detection_metrics(df['cve_extracted'], df['gt_cve'])
    cwe_metrics = calculate_detection_metrics(df['cwe_extracted'], df['gt_cwe'])

    # Calculate REIN metrics for CWE
    cwe_classifications = []
    for idx, row in df.iterrows():
        classification = classify_response_quality(
            row['cwe_extracted'], row['gt_cwe'], row[cwe_col]
        )
        cwe_classifications.append(classification)

    cwe_rein = calculate_rein_metrics(cwe_classifications)

    # Calculate REIN metrics for CVE
    cve_classifications = []
    for idx, row in df.iterrows():
        classification = classify_response_quality(
            row['cve_extracted'], row['gt_cve'], row[cve_col]
        )
        cve_classifications.append(classification)

    cve_rein = calculate_rein_metrics(cve_classifications)

    return {
        'model': model_name.capitalize() if '-' not in model_name else model_name.title().replace('-', '-'),
        'language': language.capitalize(),
        'samples': len(df),
        # CVE Detection
        'cve_precision': cve_metrics['precision'],
        'cve_recall': cve_metrics['recall'],
        'cve_f1': cve_metrics['f1'],
        # CWE Detection
        'cwe_precision': cwe_metrics['precision'],
        'cwe_recall': cwe_metrics['recall'],
        'cwe_f1': cwe_metrics['f1'],
        # CWE REIN
        'cwe_reinp': cwe_rein['reinp'],
        'cwe_reinr': cwe_rein['reinr'],
        'cwe_reinf1': cwe_rein['reinf1'],
        'cwe_rein_rate': cwe_rein['rein_rate'],
        'cwe_rein_fn_rate': cwe_rein['rein_fn_rate'],
        'cwe_ui': cwe_rein['ui'],
        'cwe_ni': cwe_rein['ni'],
        'cwe_mi': cwe_rein['mi'],
        # CVE REIN
        'cve_reinp': cve_rein['reinp'],
        'cve_reinr': cve_rein['reinr'],
        'cve_reinf1': cve_rein['reinf1'],
    }

# Find all result files
print("="*100)
print("COMPREHENSIVE ANALYSIS OF ALL COLAB RESULTS")
print("="*100)

# Get unique files (prefer most recent if duplicates)
result_files = {}
for filepath in Path(RESULTS_DIR).glob('*_results_*.csv'):
    filename = filepath.name
    # Extract model_language key
    parts = filename.replace('_results_', '_').split('_')
    model = parts[0]
    lang = parts[1]

    # Handle qwen3-coder special case
    if model == 'qwen3' and len(parts) > 2 and parts[1] == 'coder':
        model = 'qwen3-coder'
        lang = parts[2]

    key = f"{model}_{lang}"

    # Keep most recent file (higher timestamp)
    if key not in result_files or filename > result_files[key].name:
        result_files[key] = filepath

print(f"\nFound {len(result_files)} unique model-language combinations")

# Analyze all files
results = []
for key, filepath in sorted(result_files.items()):
    print(f"  Analyzing: {filepath.name}")
    result = analyze_file(str(filepath))
    if result:
        results.append(result)

# Create DataFrame
df_results = pd.DataFrame(results)

# Sort by model and language
df_results = df_results.sort_values(['model', 'language'])

# Save complete results
df_results.to_csv('complete_analysis_results.csv', index=False)

# Print summary tables
print("\n" + "="*100)
print("CWE DETECTION METRICS (F1-Score)")
print("="*100)

# Pivot table for CWE F1
cwe_f1_pivot = df_results.pivot_table(
    values='cwe_f1',
    index='model',
    columns='language',
    aggfunc='first'
)
cwe_f1_pivot = cwe_f1_pivot.fillna(0)
cwe_f1_pivot['Average'] = cwe_f1_pivot.mean(axis=1)
cwe_f1_pivot = cwe_f1_pivot.sort_values('Average', ascending=False)

print("\nCWE F1-Score by Model and Language:")
print("-"*100)
formatted = cwe_f1_pivot.copy()
for col in formatted.columns:
    formatted[col] = formatted[col].apply(lambda x: f"{x*100:.2f}%")
print(formatted.to_string())

# CWE REINF1
print("\n" + "="*100)
print("CWE RELEVANT INFORMATION F1 (REINF1)")
print("="*100)

cwe_reinf1_pivot = df_results.pivot_table(
    values='cwe_reinf1',
    index='model',
    columns='language',
    aggfunc='first'
)
cwe_reinf1_pivot = cwe_reinf1_pivot.fillna(0)
cwe_reinf1_pivot['Average'] = cwe_reinf1_pivot.mean(axis=1)
cwe_reinf1_pivot = cwe_reinf1_pivot.sort_values('Average', ascending=False)

print("\nCWE REINF1 by Model and Language:")
print("-"*100)
formatted = cwe_reinf1_pivot.copy()
for col in formatted.columns:
    formatted[col] = formatted[col].apply(lambda x: f"{x*100:.2f}%")
print(formatted.to_string())

# Model Rankings
print("\n" + "="*100)
print("MODEL RANKINGS")
print("="*100)

print("\nRanking by Average CWE F1-Score:")
avg_cwe_f1 = df_results.groupby('model')['cwe_f1'].mean().sort_values(ascending=False)
for idx, (model, f1) in enumerate(avg_cwe_f1.items(), 1):
    print(f"  {idx}. {model:15} {f1*100:.2f}%")

print("\nRanking by Average CWE REINF1:")
avg_reinf1 = df_results.groupby('model')['cwe_reinf1'].mean().sort_values(ascending=False)
for idx, (model, reinf1) in enumerate(avg_reinf1.items(), 1):
    print(f"  {idx}. {model:15} {reinf1*100:.2f}%")

# Language comparison
print("\n" + "="*100)
print("LANGUAGE COMPARISON")
print("="*100)

print("\nAverage CWE F1 by Language:")
avg_by_lang = df_results.groupby('language')['cwe_f1'].mean().sort_values(ascending=False)
for lang, f1 in avg_by_lang.items():
    print(f"  {lang:10} {f1*100:.2f}%")

print("\nAverage CWE REINF1 by Language:")
avg_reinf1_by_lang = df_results.groupby('language')['cwe_reinf1'].mean().sort_values(ascending=False)
for lang, reinf1 in avg_reinf1_by_lang.items():
    print(f"  {lang:10} {reinf1*100:.2f}%")

# Best per language
print("\n" + "="*100)
print("BEST MODEL PER LANGUAGE")
print("="*100)

for lang in df_results['language'].unique():
    lang_data = df_results[df_results['language'] == lang]
    best_f1 = lang_data.loc[lang_data['cwe_f1'].idxmax()]
    best_reinf1 = lang_data.loc[lang_data['cwe_reinf1'].idxmax()]
    print(f"\n{lang}:")
    print(f"  Best CWE F1:    {best_f1['model']:15} F1={best_f1['cwe_f1']*100:.2f}%")
    print(f"  Best REINF1:    {best_reinf1['model']:15} REINF1={best_reinf1['cwe_reinf1']*100:.2f}%")

# Save pivot tables
cwe_f1_pivot.to_csv('cwe_f1_pivot_table.csv')
cwe_reinf1_pivot.to_csv('cwe_reinf1_pivot_table.csv')

print("\n" + "="*100)
print("[SAVED] Results saved to:")
print("  - complete_analysis_results.csv")
print("  - cwe_f1_pivot_table.csv")
print("  - cwe_reinf1_pivot_table.csv")
print("="*100)
