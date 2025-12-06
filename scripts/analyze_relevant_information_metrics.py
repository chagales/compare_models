"""
Comprehensive Analysis of Relevant Information Metrics (REIN)
Calculates: REINP, REINR, REINF1, REIN Rate, REIN FN Rate

Based on paper definitions:
- REINP: Proportion of answers with relevant information (Ui / (Ui + Ni))
- REINR: Ability to identify relevant information (Ui / (Ui + Mi))
- REINF1: F1 score of relevant information
- REIN Rate: Proportion of irrelevant/incorrect info (Ni / (Ui + Ni))
- REIN FN Rate: Proportion where model didn't provide useful info (Mi / (Ui + Mi))

Where:
- Ui: Number of useful answers with relevant information
- Ni: Number of answers with irrelevant or incorrect information
- Mi: Number of responses where model didn't provide useful info
"""
import pandas as pd
import re
import ast
import os

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

def classify_response_quality(predicted, ground_truth, response_text):
    """
    Classify response quality for REIN metrics.

    Returns:
    - 'useful': Response contains relevant/correct information (at least partial match)
    - 'irrelevant': Response contains codes but all incorrect
    - 'missing': Response doesn't provide useful information (empty or no codes)
    """
    pred_set = set(predicted) if predicted else set()
    gt_set = set(ground_truth) if ground_truth else set()

    # Check if response has any content
    if pd.isna(response_text) or response_text == "ERROR" or str(response_text).strip() == "":
        return 'missing'

    # Check if any codes were extracted
    if not pred_set:
        # No codes extracted, but check if response has content
        if len(str(response_text)) > 50:  # Has substantial text
            return 'irrelevant'  # Responded but no useful codes
        else:
            return 'missing'  # Empty or very short response

    # Codes were extracted
    if pred_set & gt_set:  # At least one correct code
        return 'useful'
    else:  # All codes are incorrect
        return 'irrelevant'

def calculate_rein_metrics(df, response_col, gt_col, metric_type='CWE'):
    """Calculate REIN metrics for a dataset."""

    # Classify each response
    classifications = []
    for idx, row in df.iterrows():
        predicted = row[f'{metric_type.lower()}_extracted']
        ground_truth = row[gt_col]
        response = row[response_col]

        classification = classify_response_quality(predicted, ground_truth, response)
        classifications.append(classification)

    # Count classifications
    ui = classifications.count('useful')      # Useful answers
    ni = classifications.count('irrelevant')  # Irrelevant/incorrect
    mi = classifications.count('missing')     # Missing useful info

    total_samples = len(classifications)

    # Calculate REIN metrics
    reinp = ui / (ui + ni) if (ui + ni) > 0 else 0.0
    reinr = ui / (ui + mi) if (ui + mi) > 0 else 0.0
    reinf1 = 2 * (reinp * reinr) / (reinp + reinr) if (reinp + reinr) > 0 else 0.0
    rein_rate = ni / (ui + ni) if (ui + ni) > 0 else 0.0
    rein_fn_rate = mi / (ui + mi) if (ui + mi) > 0 else 0.0

    return {
        'ui': ui,
        'ni': ni,
        'mi': mi,
        'total': total_samples,
        'reinp': reinp,
        'reinr': reinr,
        'reinf1': reinf1,
        'rein_rate': rein_rate,
        'rein_fn_rate': rein_fn_rate
    }

def analyze_file_rein(filepath, model_name, language):
    """Analyze REIN metrics for a single results file."""
    print(f"\n{'='*80}")
    print(f"Analyzing REIN Metrics: {model_name} - {language.upper()}")
    print(f"{'='*80}")

    # Load file
    if filepath.endswith('.xlsx'):
        df = pd.read_excel(filepath)
    else:
        df = pd.read_csv(filepath)

    print(f"Loaded: {len(df)} rows")

    # Determine column names
    model_key = model_name.lower().replace('-', '').replace(' ', '')
    cve_response_col = f'{model_key}_CVE_response'
    cwe_response_col = f'{model_key}_CWE_response'

    # Check if columns exist
    if cve_response_col not in df.columns:
        possible_cve = [col for col in df.columns if 'cve' in col.lower() and 'response' in col.lower()]
        possible_cwe = [col for col in df.columns if 'cwe' in col.lower() and 'response' in col.lower()]
        if possible_cve and possible_cwe:
            cve_response_col = possible_cve[0]
            cwe_response_col = possible_cwe[0]
        else:
            print(f"ERROR: Could not find response columns")
            return None

    # Apply extraction
    df['cve_extracted'] = df[cve_response_col].apply(extract_cve_codes)
    df['cwe_extracted'] = df[cwe_response_col].apply(extract_cwe_codes)

    # Parse ground truth
    df['gt_cve'] = df['cve_id'].apply(parse_ground_truth)
    df['gt_cwe'] = df['cwe_id'].apply(parse_ground_truth)

    # Calculate REIN metrics for CVE
    cve_rein = calculate_rein_metrics(df, cve_response_col, 'gt_cve', 'CVE')

    # Calculate REIN metrics for CWE
    cwe_rein = calculate_rein_metrics(df, cwe_response_col, 'gt_cwe', 'CWE')

    # Print results
    print(f"\nCVE - Relevant Information Metrics:")
    print(f"  Useful (Ui):        {cve_rein['ui']:3d} / {cve_rein['total']}")
    print(f"  Irrelevant (Ni):    {cve_rein['ni']:3d} / {cve_rein['total']}")
    print(f"  Missing (Mi):       {cve_rein['mi']:3d} / {cve_rein['total']}")
    print(f"  REINP:              {cve_rein['reinp']:.4f} ({cve_rein['reinp']*100:.2f}%)")
    print(f"  REINR:              {cve_rein['reinr']:.4f} ({cve_rein['reinr']*100:.2f}%)")
    print(f"  REINF1:             {cve_rein['reinf1']:.4f} ({cve_rein['reinf1']*100:.2f}%)")
    print(f"  REIN Rate:          {cve_rein['rein_rate']:.4f} ({cve_rein['rein_rate']*100:.2f}%)")
    print(f"  REIN FN Rate:       {cve_rein['rein_fn_rate']:.4f} ({cve_rein['rein_fn_rate']*100:.2f}%)")

    print(f"\nCWE - Relevant Information Metrics:")
    print(f"  Useful (Ui):        {cwe_rein['ui']:3d} / {cwe_rein['total']}")
    print(f"  Irrelevant (Ni):    {cwe_rein['ni']:3d} / {cwe_rein['total']}")
    print(f"  Missing (Mi):       {cwe_rein['mi']:3d} / {cwe_rein['total']}")
    print(f"  REINP:              {cwe_rein['reinp']:.4f} ({cwe_rein['reinp']*100:.2f}%)")
    print(f"  REINR:              {cwe_rein['reinr']:.4f} ({cwe_rein['reinr']*100:.2f}%)")
    print(f"  REINF1:             {cwe_rein['reinf1']:.4f} ({cwe_rein['reinf1']*100:.2f}%)")
    print(f"  REIN Rate:          {cwe_rein['rein_rate']:.4f} ({cwe_rein['rein_rate']*100:.2f}%)")
    print(f"  REIN FN Rate:       {cwe_rein['rein_fn_rate']:.4f} ({cwe_rein['rein_fn_rate']*100:.2f}%)")

    return {
        'model': model_name,
        'language': language,
        'samples': len(df),
        # CVE REIN
        'cve_ui': cve_rein['ui'],
        'cve_ni': cve_rein['ni'],
        'cve_mi': cve_rein['mi'],
        'cve_reinp': cve_rein['reinp'],
        'cve_reinr': cve_rein['reinr'],
        'cve_reinf1': cve_rein['reinf1'],
        'cve_rein_rate': cve_rein['rein_rate'],
        'cve_rein_fn_rate': cve_rein['rein_fn_rate'],
        # CWE REIN
        'cwe_ui': cwe_rein['ui'],
        'cwe_ni': cwe_rein['ni'],
        'cwe_mi': cwe_rein['mi'],
        'cwe_reinp': cwe_rein['reinp'],
        'cwe_reinr': cwe_rein['reinr'],
        'cwe_reinf1': cwe_rein['reinf1'],
        'cwe_rein_rate': cwe_rein['rein_rate'],
        'cwe_rein_fn_rate': cwe_rein['rein_fn_rate'],
    }

# Files to analyze
files_to_analyze = [
    ('llama3_c_results_20251120_173126.csv', 'Llama3', 'C'),
    ('llama3_python_results_20251120_175952.csv', 'Llama3', 'Python'),
    ('gemma2_c_results_20251120_182905.csv', 'Gemma2', 'C'),
    ('gemma2_python_results_20251120_191632.csv', 'Gemma2', 'Python'),
    ('mistral_c_results_20251120_195827.csv', 'Mistral', 'C'),
    ('mistral_python_results_20251120_203716.csv', 'Mistral', 'Python'),
    ('codegemma_c_results_20251120_092248.xlsx', 'CodeGemma', 'C'),
]

print("="*80)
print("RELEVANT INFORMATION METRICS ANALYSIS - ALL MODELS")
print("="*80)

# Analyze all files
results = []
for filename, model, lang in files_to_analyze:
    if os.path.exists(filename):
        result = analyze_file_rein(filename, model, lang)
        if result:
            results.append(result)
    else:
        print(f"\n[WARNING] File not found: {filename}")

# Create summary DataFrame
if results:
    summary_df = pd.DataFrame(results)

    print("\n" + "="*80)
    print("SUMMARY TABLE - RELEVANT INFORMATION METRICS")
    print("="*80)

    # Sort by model and language
    summary_df = summary_df.sort_values(['model', 'language'])

    # CWE REIN Summary
    print("\n" + "-"*80)
    print("CWE - Relevant Information Metrics Summary")
    print("-"*80)
    cwe_cols = ['model', 'language', 'cwe_reinp', 'cwe_reinr', 'cwe_reinf1', 'cwe_rein_rate', 'cwe_rein_fn_rate']
    cwe_table = summary_df[cwe_cols].copy()
    cwe_table['cwe_reinp'] = cwe_table['cwe_reinp'].apply(lambda x: f"{x*100:.2f}%")
    cwe_table['cwe_reinr'] = cwe_table['cwe_reinr'].apply(lambda x: f"{x*100:.2f}%")
    cwe_table['cwe_reinf1'] = cwe_table['cwe_reinf1'].apply(lambda x: f"{x*100:.2f}%")
    cwe_table['cwe_rein_rate'] = cwe_table['cwe_rein_rate'].apply(lambda x: f"{x*100:.2f}%")
    cwe_table['cwe_rein_fn_rate'] = cwe_table['cwe_rein_fn_rate'].apply(lambda x: f"{x*100:.2f}%")
    cwe_table.columns = ['Model', 'Language', 'REINP', 'REINR', 'REINF1', 'REIN Rate', 'REIN FN Rate']
    print(cwe_table.to_string(index=False))

    # CVE REIN Summary
    print("\n" + "-"*80)
    print("CVE - Relevant Information Metrics Summary")
    print("-"*80)
    cve_cols = ['model', 'language', 'cve_reinp', 'cve_reinr', 'cve_reinf1', 'cve_rein_rate', 'cve_rein_fn_rate']
    cve_table = summary_df[cve_cols].copy()
    cve_table['cve_reinp'] = cve_table['cve_reinp'].apply(lambda x: f"{x*100:.2f}%")
    cve_table['cve_reinr'] = cve_table['cve_reinr'].apply(lambda x: f"{x*100:.2f}%")
    cve_table['cve_reinf1'] = cve_table['cve_reinf1'].apply(lambda x: f"{x*100:.2f}%")
    cve_table['cve_rein_rate'] = cve_table['cve_rein_rate'].apply(lambda x: f"{x*100:.2f}%")
    cve_table['cve_rein_fn_rate'] = cve_table['cve_rein_fn_rate'].apply(lambda x: f"{x*100:.2f}%")
    cve_table.columns = ['Model', 'Language', 'REINP', 'REINR', 'REINF1', 'REIN Rate', 'REIN FN Rate']
    print(cve_table.to_string(index=False))

    # Key findings
    print("\n" + "="*80)
    print("KEY INSIGHTS - RELEVANT INFORMATION QUALITY")
    print("="*80)

    # Best REINP for CWE
    print("\nBest CWE REINP (Precision of Relevant Info) by Language:")
    for lang in summary_df['language'].unique():
        lang_data = summary_df[summary_df['language'] == lang]
        best = lang_data.loc[lang_data['cwe_reinp'].idxmax()]
        print(f"  {lang:8}: {best['model']:15} REINP={best['cwe_reinp']*100:.2f}%  "
              f"(Useful={best['cwe_ui']}, Irrelevant={best['cwe_ni']})")

    # Best REINR for CWE
    print("\nBest CWE REINR (Recall of Relevant Info) by Language:")
    for lang in summary_df['language'].unique():
        lang_data = summary_df[summary_df['language'] == lang]
        best = lang_data.loc[lang_data['cwe_reinr'].idxmax()]
        print(f"  {lang:8}: {best['model']:15} REINR={best['cwe_reinr']*100:.2f}%  "
              f"(Useful={best['cwe_ui']}, Missing={best['cwe_mi']})")

    # Overall quality ranking
    print("\nModel Ranking by CWE REINF1 (Overall Info Quality):")
    model_reinf1 = summary_df.groupby('model')['cwe_reinf1'].mean().sort_values(ascending=False)
    for idx, (model, reinf1) in enumerate(model_reinf1.items(), 1):
        print(f"  {idx}. {model:15} REINF1={reinf1*100:.2f}%")

    # Comparison: C vs Python
    print("\nC vs Python - CWE Information Quality:")
    for lang in ['C', 'Python']:
        if lang in summary_df['language'].values:
            lang_data = summary_df[summary_df['language'] == lang]
            avg_reinp = lang_data['cwe_reinp'].mean()
            avg_reinr = lang_data['cwe_reinr'].mean()
            avg_reinf1 = lang_data['cwe_reinf1'].mean()
            print(f"  {lang:8}: REINP={avg_reinp*100:.2f}%, REINR={avg_reinr*100:.2f}%, REINF1={avg_reinf1*100:.2f}%")

    # Save to CSV
    summary_df.to_csv('rein_metrics_summary_all_models.csv', index=False)
    print("\n[SAVED] Results saved to: rein_metrics_summary_all_models.csv")

else:
    print("\n[ERROR] No results to summarize")

print("\n" + "="*80)
print("REIN METRICS ANALYSIS COMPLETE")
print("="*80)
