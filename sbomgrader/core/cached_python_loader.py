import sys
from pathlib import Path

from runpy import run_path
from typing import Callable, Union


class PythonLoader:
    def __init__(self, *file_references: str | Path):
        self._unloaded_file_references: set[Path] = set()
        self._loaded_file_references: set[Path] = set()
        self.__functions: dict[str, Callable] = {}

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
            module = run_path(str(ref.absolute()))
            self.__functions.update(
                {name: value for name, value in module.items() if callable(value)}
            )
        self._loaded_file_references.update(self._unloaded_file_references)
        self._unloaded_file_references = set()

    @property
    def file_references(self) -> set[Path]:
        return self._unloaded_file_references | self._loaded_file_references

    def load_func(self, name: str) -> Union[Callable, None]:
        if self._unloaded_file_references:
            self._load_all_references()
        if name not in self.__functions:
            print(
                f"Could not load transformer {name} from files {self.file_references}.",
                file=sys.stderr,
            )
        return self.__functions.get(name, None)
