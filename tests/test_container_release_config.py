from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r"^\d{2}\.\d{2}\.\d{2}$")


def _app_version() -> str:
    namespace: dict[str, object] = {}
    exec((ROOT / "app" / "version.py").read_text(encoding="utf-8"), namespace)
    return str(namespace["APP_VERSION"])


def test_release_version_is_consistent_across_deployment_files() -> None:
    version = _app_version()
    assert VERSION_PATTERN.fullmatch(version)

    compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    env_text = (ROOT / ".env.example").read_text(encoding="utf-8")
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog_text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert f"${{TIMEBOARDAPP_TAG:-{version}}}" in compose_text
    assert f"TIMEBOARDAPP_TAG={version}" in env_text
    assert f"Current version: **{version}**" in readme_text
    assert f"## {version}" in changelog_text


def test_compose_uses_ghcr_image_without_local_build() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["app"]

    assert "build" not in service
    assert service["image"].startswith(
        "${TIMEBOARDAPP_IMAGE:-ghcr.io/paulkakell/timeboardapp}:"
    )
    assert service["pull_policy"] == "always"
    assert service["container_name"] == "${CONTAINER_NAME:-timeboardapp}"


def test_compose_uses_unique_container_name_as_proxy_alias() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service_networks = compose["services"]["app"]["networks"]

    for network_name in ("net_internal", "net_external"):
        assert service_networks[network_name]["aliases"] == [
            "${CONTAINER_NAME:-timeboardapp}"
        ]


def test_runtime_jwt_dependency_avoids_python_ecdsa_stack() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    normalized = requirements.lower()
    auth_source = (ROOT / "app" / "auth.py").read_text(encoding="utf-8")

    assert "pyjwt>=2.10,<3.0" in normalized
    assert "python-jose" not in normalized
    assert not any(
        line.strip().lower().startswith("ecdsa")
        for line in requirements.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    assert "from jose" not in auth_source
    assert "from jwt.exceptions import InvalidTokenError" in auth_source
    assert 'algorithms=["HS256"]' in auth_source


def test_workflow_validates_before_publishing_to_ghcr() -> None:
    workflow = (ROOT / ".github" / "workflows" / "docker-image.yml").read_text(
        encoding="utf-8"
    )

    required_fragments = (
        "packages: write",
        "pytest -q",
        "bandit -r app -ll -q",
        "pip-audit -r /tmp/timeboardapp-requirements.txt",
        "docker compose config",
        "docker build --pull --tag timeboardapp:ci .",
        "docker/login-action@v3",
        "docker/metadata-action@v5",
        "docker/build-push-action@v6",
        "IMAGE_NAME: paulkakell/timeboardapp",
        "platforms: linux/amd64,linux/arm64",
        "provenance: mode=max",
        "sbom: true",
    )

    for fragment in required_fragments:
        assert fragment in workflow

    assert workflow.index("needs: validate") < workflow.index("push: true")
