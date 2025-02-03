from pathlib import Path

from sbomgrader.core.cached_python_loader import PythonLoader


class RuleLoader(PythonLoader):
    def __init__(self, implementation: str, *file_references: str | Path):
        super().__init__(*file_references)
        self.implementation: str = implementation
