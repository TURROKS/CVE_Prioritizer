from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from datetime import datetime
import os


def generate_report(data, output_path="report.html", format="html"):
    # Set the path to the templates folder
    template_dir = Path(__file__).resolve().parent.parent / "docs" / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))

    # Load the dashboard-style template
    template = env.get_template("report_template.html")

    # Render the HTML with provided data
    rendered_html = template.render(
        metadata=data.get("metadata", {}),
        cves=data.get("cves", [])
    )

    # Output as HTML
    if format == "html":
        with open(output_path, "w") as f:
            f.write(rendered_html)
        print(f"✅ HTML report saved to: {output_path}")

    # Optional: Output as PDF using WeasyPrint
    elif format == "pdf":
        try:
            from weasyprint import HTML
            HTML(string=rendered_html).write_pdf(output_path)
            print(f"✅ PDF report saved to: {output_path}")
        except ImportError:
            print("❌ Could not generate PDF. Install WeasyPrint: pip install weasyprint")
