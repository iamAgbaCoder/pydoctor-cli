from pydoctor.core.project import ProjectContext
from pydoctor.scanners.ci_scanner import scan


def test_scan_for_secrets(tmp_path):
    # Create fake project with a secret
    secret_file = tmp_path / "config.py"
    secret_file.write_text('AWS_SECRET_KEY = "AKIA1234567890ABCDEF"')

    ctx = ProjectContext(root=tmp_path, python_files=[secret_file])
    issues = scan(ctx)

    # Filter out the "OK" issue if it exists (though usually it shouldn't if there are findings)
    findings = [i for i in issues if i.severity != "ok"]

    assert len(findings) >= 1
    assert any("Secret Exposed" in i.title for i in findings)


def test_scan_workflows(tmp_path):
    # Create a GitHub action workflow with unpinned version
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow_file = workflow_dir / "main.yml"
    workflow_file.write_text("uses: actions/checkout@main")

    ctx = ProjectContext(root=tmp_path, python_files=[])
    issues = scan(ctx)

    findings = [i for i in issues if i.severity != "ok"]
    assert any("Unpinned GitHub Action" in i.title for i in findings)


def test_scan_clean_project(tmp_path):
    ctx = ProjectContext(root=tmp_path, python_files=[])
    issues = scan(ctx)

    assert len(issues) == 1
    assert issues[0].code == "CI_HEALTHY"
