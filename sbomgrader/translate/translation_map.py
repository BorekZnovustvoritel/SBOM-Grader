import re
from pathlib import Path
from typing import Any, Callable

from black.trans import defaultdict

from sbomgrader.core.cached_python_loader import PythonLoader
from sbomgrader.core.enums import Implementation
from sbomgrader.core.field_resolve import Variable, FieldResolver


class Template:
    def __init__(self, source: Any):
        self.source = source
        self.__fields_with_vars: dict[str, list[Any]] = defaultdict(list)

    def _scan_for_vars(self, item: Any):
        if isinstance(item, str) and (occurrences := re.findall(r"\$\{(?P<varname>\S+)}", item)):
            for occ in occurrences:
                self.__fields_with_vars[occ].append(item)

    @staticmethod
    def _scout_data(data, func: Callable[[Any], Any]) -> Any:
        if isinstance(data, list):
            for item in data:
                Template._scout_data(item, func)
        elif isinstance(data, dict):
            for item in data.values():
                Template._scout_data(item, func)
        else:
            func(data)

    @property
    def variable_names(self) -> list[str]:
        if not self.__fields_with_vars:
            self._scout_data(self.source, self._scan_for_vars)
        return list(self.__fields_with_vars.keys())





class Data:
    def __init__(self, template: Template, variables: list[Variable]):
        self.variables = variables
        self.template = template
        self.field_resolver = FieldResolver()



class Chunk:
    def __init__(
        self,
    ):
        pass


class TranslationMap:
    def __init__(
        self, first: Implementation, second: Implementation, chunks: list[Chunk]
    ):
        self.first = first
        self.second = second
        self.chunks = chunks
        self.field_resolver = FieldResolver()


class TransformerMapLoader(PythonLoader):
    def __init__(self, *file_references: str | Path):
        super().__init__(*file_references)
