import typer
import pandas as pd
from pathlib import Path
from tqdm import tqdm

from pii_utils.detector import find_pii
from pii_utils.anonymizer import anonymize_pii

app = typer.Typer()

@app.command()
def process_file(
    input_file: Path = typer.Option(..., "--input", "-i", help="Path to the input CSV file."),
    output_dir: Path = typer.Option("output", "--output", "-o", help="Directory to save the output files.")
):
    # --- Security & Edge Case: Validate Input File ---
    if not input_file.exists():
        print(f"❌ Error: Input file not found at {input_file}")
        raise typer.Exit(code=1)
    
    # --- Security (OWASP): Prevent Path Traversal ---
    try:
        input_file.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        print(f"❌ Security Error: Input file is outside the project directory. Aborting.")
        raise typer.Exit(code=1)

    # --- Edge Case: Create output directory if it doesn't exist ---
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"deidentified_{input_file.name}"

    # --- Core Logic using Pandas for robust CSV handling ---
    df = pd.read_csv(input_file, dtype=str).fillna('')
    total_pii_found = 0

    # --- Suggestion: Professional progress bar for large files ---
    for col in tqdm(df.columns, desc="Processing Columns"):
        for i, cell_text in enumerate(df[col]):
            if not cell_text:
                continue

            pii_results = find_pii(cell_text)
            if pii_results:
                total_pii_found += len(pii_results)
                modified_text = cell_text
                for pii in pii_results:
                    anonymized_value = anonymize_pii(pii['type'], pii['value'])
                    modified_text = modified_text.replace(pii['value'], anonymized_value)
                df.loc[i, col] = modified_text

    # --- Reporting ---
    df.to_csv(output_file, index=False)
    print(f"\n✅ Processing complete!")
    print(f"Found and de-identified {total_pii_found} PII instances.")
    print(f"Output saved to: {output_file}")

if __name__ == "__main__":
    app()