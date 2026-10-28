"""pydoctor/core/__init__.py"""

from pydoctor.core.project import ProjectContext
from pydoctor.core.report import DiagnosisReport, Issue

__all__ = ["Issue", "DiagnosisReport", "ProjectContext", "Analyzer"]


def __getattr__(name: str):
    # Imported lazily: Analyzer imports every scanner, and scanners import
    # pydoctor.core, so an eager import here made
    # `import pydoctor.scanners.vulnerability_scanner` fail with a circular import.
    if name == "Analyzer":
        from pydoctor.core.analyzer import Analyzer

        return Analyzer
    raise AttributeError(name)
