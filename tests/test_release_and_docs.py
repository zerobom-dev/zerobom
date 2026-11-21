"""Offline verification tests for Phase 3 packaging, CLI --version, Zensical docs, & workflows."""

from __future__ import annotations

import importlib
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml
from typer.testing import CliRunner

import zerobom
from zerobom import cli

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER = CliRunner()

_MD_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
_FENCED_CODE_RE = re.compile(r"```.*?```", re.DOTALL)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _iter_nav_paths(nav_entries: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(nav_entries, str):
        paths.append(nav_entries)
    elif isinstance(nav_entries, list):
        for entry in nav_entries:
            paths.extend(_iter_nav_paths(entry))
    elif isinstance(nav_entries, dict):
        for value in nav_entries.values():
            paths.extend(_iter_nav_paths(value))
    return paths


class TestCliVersionAndPackagingMetadata:
    def test_cli_version_flag_matches_package_and_pyproject(self) -> None:
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        expected_version = pyproject["project"]["version"]
        assert zerobom.__version__ == expected_version

        for flag in ("--version", "-V"):
            res = RUNNER.invoke(cli.app, [flag])
            assert res.exit_code == cli.EXIT_OK
            assert res.stdout.strip() == f"zerobom {expected_version}"

        res_help = RUNNER.invoke(
            cli.app,
            ["--help"],
            env={"NO_COLOR": "1", "TERM": "dumb"},
        )
        assert res_help.exit_code == cli.EXIT_OK
        assert "--version" in _ANSI_RE.sub("", res_help.stdout)

    def test_pep621_metadata_license_and_typed_markers_across_packages(self) -> None:
        package_specs = [
            (REPO_ROOT, REPO_ROOT / "src" / "zerobom"),
            (
                REPO_ROOT / "plugins" / "zerobom-aws",
                REPO_ROOT / "plugins" / "zerobom-aws" / "src" / "zerobom_aws",
            ),
            (
                REPO_ROOT / "plugins" / "zerobom-gcp",
                REPO_ROOT / "plugins" / "zerobom-gcp" / "src" / "zerobom_gcp",
            ),
            (
                REPO_ROOT / "plugins" / "zerobom-azure",
                REPO_ROOT / "plugins" / "zerobom-azure" / "src" / "zerobom_azure",
            ),
        ]
        for pkg_root, src_pkg in package_specs:
            manifest = tomllib.loads((pkg_root / "pyproject.toml").read_text(encoding="utf-8"))
            project = manifest["project"]
            assert project["license"] == "Apache-2.0"
            assert "LICENSE" in project["license-files"]
            assert (pkg_root / "LICENSE").is_file()
            assert (pkg_root / project["readme"]).is_file()
            assert (src_pkg / "py.typed").is_file()
            assert project["classifiers"]
            for url_val in project["urls"].values():
                assert url_val.startswith("https://")
                assert "<" not in url_val and ">" not in url_val

        root_manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        core_deps = "\n".join(root_manifest["project"]["dependencies"]).lower()
        for forbidden in ("boto3", "google-", "azure-", "zensical", "mkdocs", "slack-sdk"):
            assert forbidden not in core_deps

        docs_deps = "\n".join(root_manifest["dependency-groups"]["docs"]).lower()
        assert "zensical" in docs_deps
        assert "mkdocstrings-python" in docs_deps


class TestZensicalDocsAndCommunityAssets:
    def test_zensical_toml_nav_mkdocstrings_and_relative_links(self) -> None:
        zensical_cfg = tomllib.loads((REPO_ROOT / "zensical.toml").read_text(encoding="utf-8"))
        proj = zensical_cfg["project"]
        assert proj["docs_dir"] == "docs"
        assert proj["site_url"].startswith("https://")
        assert "<" not in proj["site_url"] and ">" not in proj["site_url"]
        for excluded in ("PHASE2_PLAN.md", "LAUNCH_KIT.md"):
            assert excluded not in proj["exclude_docs"]
        assert "ROADMAP.md" in proj["exclude_docs"]

        py_handler = proj["plugins"]["mkdocstrings"]["handlers"]["python"]
        assert py_handler["paths"] == [
            "src",
            "plugins/zerobom-aws/src",
            "plugins/zerobom-gcp/src",
            "plugins/zerobom-azure/src",
        ]

        docs_dir = REPO_ROOT / "docs"
        nav_files = _iter_nav_paths(proj["nav"])
        assert len(nav_files) >= 15
        for rel_md in nav_files:
            md_path = docs_dir / rel_md
            assert md_path.is_file(), f"Missing Zensical nav page: {md_path}"

        api_files = sorted((docs_dir / "api").glob("*.md"))
        assert len(api_files) == 8
        for api_md in api_files:
            matches = re.findall(
                r"^:::\s+([A-Za-z0-9_.]+)\s*$", api_md.read_text(encoding="utf-8"), re.M
            )
            assert matches, f"No mkdocstrings directive found in {api_md}"
            for mod_name in matches:
                mod = importlib.import_module(mod_name)
                assert getattr(mod, "__doc__", None)

        # Validate markdown links and confirm zero host drive-letter file links.
        md_targets = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "CONTRIBUTING.md",
            REPO_ROOT / "SECURITY.md",
            *docs_dir.rglob("*.md"),
        ]
        for md_file in md_targets:
            raw_text = md_file.read_text(encoding="utf-8")
            assert "file:///d:/" not in raw_text.lower()
            assert "file:///c:/" not in raw_text.lower()
            stripped = _FENCED_CODE_RE.sub("", raw_text)
            for link in _MD_LINK_RE.findall(stripped):
                clean = link.split("#", 1)[0].strip()
                if not clean or clean.startswith(("http://", "https://", "mailto:")):
                    continue
                target_path = (md_file.parent / clean).resolve()
                assert target_path.exists(), f"Broken relative link {link!r} in {md_file}"

        assert (docs_dir / "assets" / "demo.tape").is_file()
        svg_path = docs_dir / "assets" / "demo-preview.svg"
        assert svg_path.is_file()
        svg_text = svg_path.read_text(encoding="utf-8")
        svg_plain = svg_text.replace("&#160;", " ")
        assert "<svg" in svg_text
        assert "PRECVE-2026-7DA3A045" in svg_plain
        assert "Example Security Research" in svg_plain
        assert "Debian:11" in svg_plain
        assert "Project Zero" not in svg_plain

    def test_community_files_issue_forms_pinning_and_workflows_valid(self) -> None:
        assert not (REPO_ROOT / "docs" / "LAUNCH_KIT.md").exists()
        assert not (REPO_ROOT / "docs" / "PHASE2_PLAN.md").exists()
        assert (REPO_ROOT / ".env.example").is_file()
        assert "r3zH@proton.me" in (REPO_ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")

        root_toml = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        sdist_include = root_toml["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
        assert "/src/zerobom" in sdist_include
        assert not any("AGENTS" in item or "plugins" in item for item in sdist_include)

        for placeholder_check in (
            REPO_ROOT / "pyproject.toml",
            REPO_ROOT / "README.md",
            REPO_ROOT / "zensical.toml",
            REPO_ROOT / "SECURITY.md",
            REPO_ROOT / "plugins" / "zerobom-aws" / "pyproject.toml",
            REPO_ROOT / "plugins" / "zerobom-gcp" / "pyproject.toml",
            REPO_ROOT / "plugins" / "zerobom-azure" / "pyproject.toml",
            *list((REPO_ROOT / "docs").rglob("*.md")),
        ):
            assert "your-org" not in placeholder_check.read_text(encoding="utf-8")

        for required_doc in (
            "README.md",
            "LICENSE",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "CHANGELOG.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
        ):
            path = REPO_ROOT / required_doc
            assert path.is_file(), f"Missing community file: {required_doc}"
            assert len(path.read_text(encoding="utf-8").strip()) > 100

        issue_templates = list((REPO_ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))
        assert len(issue_templates) == 5
        for tpl in issue_templates:
            parsed = yaml.safe_load(tpl.read_text(encoding="utf-8"))
            assert isinstance(parsed, dict)

        sha_pin_re = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@]+)?@[0-9a-f]{40}$")
        action_yml = yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))
        for step in action_yml["runs"]["steps"]:
            if "uses" in step:
                assert sha_pin_re.match(step["uses"]), f"Unpinned action: {step['uses']!r}"

        workflows_dir = REPO_ROOT / ".github" / "workflows"
        for wf_name in ("zerobom-ci.yml", "docs.yml", "render-demo.yml", "release.yml"):
            wf_path = workflows_dir / wf_name
            assert wf_path.is_file()
            wf = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
            assert wf["permissions"] == {"contents": "read"}
            for job in wf["jobs"].values():
                for step in job.get("steps", []):
                    if "uses" in step:
                        assert sha_pin_re.match(step["uses"]), (
                            f"Unpinned action in {wf_name}: {step['uses']!r}"
                        )
                    run_cmd = step.get("run")
                    if isinstance(run_cmd, str):
                        assert "${{ inputs." not in run_cmd
                        assert "${{ github." not in run_cmd
                        assert "${{ steps." not in run_cmd

        docs_wf_text = (workflows_dir / "docs.yml").read_text(encoding="utf-8")
        assert "zensical build --clean --strict" in docs_wf_text
        assert "deploy-pages" in docs_wf_text

        release_wf = yaml.safe_load((workflows_dir / "release.yml").read_text(encoding="utf-8"))
        for pub_job_name in ("publish-pypi", "publish-plugins-pypi"):
            publish_job = release_wf["jobs"][pub_job_name]
            assert publish_job["permissions"] == {"id-token": "write"}
            assert any(
                str(step.get("uses", "")).startswith("pypa/gh-action-pypi-publish@")
                for step in publish_job["steps"]
            )
