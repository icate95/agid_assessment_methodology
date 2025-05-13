"""Console script for agid_assessment_methodology."""
import agid_assessment_methodology

import typer
from rich.console import Console

app = typer.Typer()
console = Console()


@app.command()
def main():
    """Console script for agid_assessment_methodology."""
    console.print("Replace this message by putting your code into "
               "agid_assessment_methodology.cli.main")
    console.print("See Typer documentation at https://typer.tiangolo.com/")
    


if __name__ == "__main__":
    app()
