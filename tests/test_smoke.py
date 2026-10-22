"""Smoke tests for the template loader."""

from pathlib import Path

from tests.cfn import load_template


def test_load_template_reads_short_form_tags(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text(
        "Resources:\n"
        "  A:\n"
        "    Properties:\n"
        "      Ref: !Ref Foo\n"
        '      Name: !Sub "a-${B}"\n'
    )

    properties = load_template(path)["Resources"]["A"]["Properties"]

    assert properties["Ref"] == "Foo"
    assert properties["Name"] == "a-${B}"
