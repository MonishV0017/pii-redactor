import typer
import pandas as pd
from pathlib import Path
from tqdm import tqdm

from pii_utils.detector import find_pii
from pii_utils.anonymizer import anonymize_pii
from reporting.report_generator import create_summary_report

app = typer.Typer()

def calculate_validation_metrics(true_positives, false_positives, false_negatives):
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return {"tp": true_positives, "fp": false_positives, "fn": false_negatives, "precision": precision, "recall": recall, "f1_score": f1_score}

@app.command()
def process_file(
    input_file: Path = typer.Option(..., "--input", "-i", help="Path to the input CSV file."),
    output_dir: Path = typer.Option("output", "--output", "-o", help="Directory to save the output files.")
):
    if not input_file.exists():
        print(f"❌ Error: Input file not found at {input_file}")
        raise typer.Exit(code=1)
    
    try:
        input_file.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        print(f"❌ Security Error: Input file is outside the project directory. Aborting.")
        raise typer.Exit(code=1)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"deidentified_{input_file.name}"

    df = pd.read_csv(input_file, dtype=str).fillna('')
    all_pii_found = []
    validation_mode = 'pii_type' in df.columns
    
    tp, fp, fn = 0, 0, 0

    for col in tqdm(df.columns, desc="Processing Columns"):
        if col == 'pii_type':
            continue
        
        for i, cell_text in enumerate(df[col]):
            if not cell_text:
                continue

            pii_results = find_pii(cell_text)
            
            if validation_mode:
                true_pii_type = df.loc[i, 'pii_type']
                detected_types = {p['type'] for p in pii_results}
                
                if true_pii_type in detected_types:
                    tp += 1
                else:
                    fn += 1 # We missed the true PII
                fp += len(detected_types - {true_pii_type}) # We found things that weren't the true PII
            
            if pii_results:
                all_pii_found.extend(pii_results)
                modified_text = cell_text
                for pii in pii_results:
                    anonymized_value = anonymize_pii(pii['type'], pii['value'])
                    modified_text = modified_text.replace(pii['value'], anonymized_value)
                df.loc[i, col] = modified_text

    validation_metrics = None
    if validation_mode:
        validation_metrics = calculate_validation_metrics(tp, fp, fn)

    df.to_csv(output_file, index=False)
    report_path = create_summary_report(all_pii_found, output_dir, input_file.name, validation_metrics)
    
    print(f"\n✅ Processing complete!")
    print(f"De-identified data saved to: {output_file}")
    print(f"Summary report saved to: {report_path}")

if __name__ == "__main__":
    app()