"""Helpers for reading CloudFormation templates in tests."""

from pathlib import Path
from typing import Any

import yaml


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that reads CloudFormation short-form tags as plain values."""


def _construct_tag(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    raise TypeError(f"Unexpected node: {node!r}")


_CfnLoader.add_multi_constructor("!", _construct_tag)


def load_template(path: Path) -> dict[str, Any]:
    """Load a CloudFormation template, reading short-form tags as plain values."""
    with path.open() as f:
        return yaml.load(f, Loader=_CfnLoader)
