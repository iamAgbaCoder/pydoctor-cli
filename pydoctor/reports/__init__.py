"""pydoctor/reports/__init__.py"""

from pydoctor.reports.json_formatter import render_json
from pydoctor.reports.table_formatter import render_issue_detail, render_report

__all__ = ["render_report", "render_issue_detail", "render_json"]
