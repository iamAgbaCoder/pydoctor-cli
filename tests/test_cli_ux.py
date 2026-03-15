from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from pydoctor.cli.main import app

runner = CliRunner()


def test_check_help():
    result = runner.invoke(app, ["check", "--help"])
    assert result.exit_code == 0
    assert "CI/CD guard mode" in result.stdout


def test_docker_command():
    result = runner.invoke(app, ["docker"])
    assert result.exit_code == 0
    assert "Docker Environment Doctor" in result.stdout


def test_github_command():
    # This might run a diagnose which could take time, but we'll check the initial output
    result = runner.invoke(app, ["github"])
    # If not a git repo it might exit with errors or just info
    assert "GitHub Repository Doctor" in result.stdout


def test_diagnose_prompt_no_venv(tmp_path):
    with patch("pydoctor.cli.main.ProjectContext.from_path") as mock_from_path:
        mock_ctx = MagicMock()
        mock_ctx.in_virtualenv = False
        mock_from_path.return_value = mock_ctx

        # Test that it asks for global packages when no venv is found
        result = runner.invoke(app, ["diagnose", "--path", str(tmp_path)], input="n\n")
        assert "No virtual environment detected" in result.stdout
        assert "Cancelled" in result.stdout
