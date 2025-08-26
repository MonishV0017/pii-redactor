import typer
import pandas as pd
from pathlib import Path
import logging
import chardet
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table

from pyredact.detector import find_pii
from pyredact.anonymizer import anonymize_pii
from pyredact.report_generator import create_summary_report

console = Console()
logging.basicConfig(level="INFO", format='%(levelname)s: %(message)s', handlers=[])
logger = logging.getLogger(__name__)

app = typer.Typer(rich_markup_mode="markdown")

ASCII_BANNER = """
 ███████████  █████ █████ ███████████   ██████████ ██████████     █████████     █████████  ███████████
░░███░░░░░███░░███ ░░███ ░░███░░░░░███ ░░███░░░░░█░░███░░░░███   ███░░░░░███   ███░░░░░███░█░░░███░░░█
 ░███    ░███ ░░███ ███   ░███    ░███  ░███  █ ░  ░███   ░░███ ░███    ░███  ███     ░░░ ░   ░███  ░ 
 ░██████████   ░░█████    ░██████████   ░██████    ░███    ░███ ░███████████ ░███             ░███    
 ░███░░░░░░     ░░███     ░███░░░░░███  ░███░░█    ░███    ░███ ░███░░░░░███ ░███             ░███    
 ░███            ░███     ░███    ░███  ░███ ░   █ ░███    ███  ░███    ░███ ░░███     ███    ░███    
 █████           █████    █████   █████ ██████████ ██████████   █████   █████ ░░█████████     █████   
░░░░░           ░░░░░    ░░░░░   ░░░░░ ░░░░░░░░░░ ░░░░░░░░░░   ░░░░░   ░░░░░   ░░░░░░░░░     ░░░░░    
                                                                                                      
                                                                                                      
                                                                                                      
"""

def detect_encoding(file_path: Path) -> str:
    with open(file_path, 'rb') as f:
        raw_data = f.read(20000)
    result = chardet.detect(raw_data)
    return result['encoding'] or 'utf-8'

def calculate_validation_metrics(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1_score": f1_score}

@app.command()
def process(
    input_file: Path = typer.Option(..., "--input", "-i", help="Path to the input CSV file.", exists=True, file_okay=True, dir_okay=False, readable=True),
    output_dir: Path = typer.Option("output", "--output", "-o", help="Directory to save the output files."),
):
    console.print(f"[bold green]{ASCII_BANNER}[/bold green]")

    # --- Security (OWASP): Prevent Path Traversal ---
    try:
        input_file.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        console.print(f"❌ [bold red]Security Error:[/bold red] Input file is outside the project directory. Aborting.")
        raise typer.Exit(code=1)
    
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        console.print(f"❌ [bold red]Permission Error:[/bold red] Could not create output directory.")
        raise typer.Exit(code=1)

    try:
        encoding = detect_encoding(input_file)
        df = pd.read_csv(input_file, dtype=str, encoding=encoding, engine='python').fillna('')
    except Exception as e:
        console.print(f"❌ [bold red]File Read Error:[/bold red] Could not read CSV. Reason: {e}")
        raise typer.Exit(code=1)
    
    if df.empty:
        console.print("⚠️ [yellow]Warning:[/yellow] Input file is empty. No output generated.")
        raise typer.Exit()
        
    all_pii_found = []
    validation_mode = 'pii_type' in df.columns
    tp, fp, fn = 0, 0, 0

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
        task = progress.add_task("[green]Processing file...", total=len(df))
        for index, row in df.iterrows():
            row_text = ' '.join(row.astype(str))
            pii_results = find_pii(row_text)

            if validation_mode:
                true_pii_type = row.get('pii_type', '').upper()
                detected_types = {p['type'] for p in pii_results}
                if true_pii_type and true_pii_type in detected_types:
                    tp += 1
                    detected_types.remove(true_pii_type)
                elif true_pii_type and true_pii_type not in detected_types:
                    fn += 1
                fp += len(detected_types)
            
            if pii_results:
                all_pii_found.extend(pii_results)
                for col in df.columns:
                    if validation_mode and col == 'pii_type': continue
                    cell_text = row[col]
                    modified_text = cell_text
                    for pii in find_pii(cell_text):
                        anonymized_value = anonymize_pii(pii['type'], pii['value'])
                        modified_text = modified_text.replace(pii['value'], anonymized_value)
                    df.loc[index, col] = modified_text
            progress.update(task, advance=1)
    
    output_file = output_dir / f"deidentified_{input_file.name}"
    df.to_csv(output_file, index=False)
    
    validation_metrics = calculate_validation_metrics(tp, fp, fn) if validation_mode else None
    report_path = create_summary_report(all_pii_found, output_dir, input_file.name, validation_metrics)
    
    console.rule("[bold blue]Scan Complete[/bold blue]")
    summary_table = Table(title="Summary")
    summary_table.add_column("Item", style="cyan")
    summary_table.add_column("Details", style="magenta")
    summary_table.add_row("Total PII Found", str(len(all_pii_found)))
    summary_table.add_row("De-identified File", str(output_file))
    summary_table.add_row("Summary Report", str(report_path))
    if validation_mode:
        summary_table.add_row("[bold]F1-Score[/bold]", f"{validation_metrics['f1_score']:.2f}")
    console.print(summary_table)

if __name__ == "__main__":
    app()