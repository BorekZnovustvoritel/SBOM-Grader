from pathlib import Path

from runpy import run_path
from typing import Callable, Union


class RuleLoader:
    def __init__(self, implementation: str, *file_references: str | Path):
        self.implementation: str = implementation
        self._unloaded_file_references: set[Path] = set()
        self._loaded_file_references: set[Path] = set()
        self.functions: dict[str, Callable] = {}

        self.add_file_references(*file_references)

    def add_file_references(self, *file_references: str | Path) -> None:
        self._unloaded_file_references.update(
            ref for ref in file_references if isinstance(ref, Path)
        )
        self._unloaded_file_references.update(
            Path(ref) for ref in file_references if isinstance(ref, str)
        )

    def _load_all_references(self) -> None:
        for ref in self._unloaded_file_references:
            if not ref.exists():
                continue
            # spec = util.spec_from_file_location(self.implementation, ref)
            # module = util.module_from_spec(spec)
            module = run_path(str(ref.absolute()))
            self.functions.update(
                {name: value for name, value in module.items() if callable(value)}
            )
        self._loaded_file_references.update(self._unloaded_file_references)
        self._unloaded_file_references = set()

    @property
    def file_references(self) -> set[Path]:
        return self._unloaded_file_references | self._loaded_file_references

    def load_rule(self, name: str) -> Union[Callable, None]:
        if self._unloaded_file_references:
            self._load_all_references()
        return self.functions.get(name, None)
