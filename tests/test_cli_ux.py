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
        mock_ctx.env_error = None
        mock_from_path.return_value = mock_ctx

        # Test that it asks for global packages when no venv is found (interactive run)
        with patch("pydoctor.cli.main._is_interactive", return_value=True):
            result = runner.invoke(app, ["diagnose", "--path", str(tmp_path)], input="n\n")
        assert "No virtual environment detected" in result.stdout
        assert "Cancelled" in result.stdout


def test_diagnose_never_prompts_when_not_interactive(tmp_path):
    """CI and piped runs must not block on the no-venv prompt."""
    with (
        patch("pydoctor.cli.main.ProjectContext.from_path") as mock_from_path,
        patch("pydoctor.cli.main._run_scan") as mock_scan,
        patch("pydoctor.cli.main._output"),
        patch("pydoctor.cli.main._exit_code", return_value=0),
        patch("pydoctor.cli.main.Confirm.ask") as ask,
    ):
        mock_ctx = MagicMock()
        mock_ctx.in_virtualenv = False
        mock_ctx.env_error = None
        mock_ctx.python_executable = "/usr/bin/python3"
        mock_ctx.python_source = "`python3` on PATH"
        mock_from_path.return_value = mock_ctx
        result = runner.invoke(app, ["diagnose", "--path", str(tmp_path)])
        assert "No virtual environment detected" in result.stdout
        ask.assert_not_called()
        mock_scan.assert_called_once()


def test_github_says_remote_repos_are_not_supported(tmp_path):
    with (
        patch("pydoctor.cli.main._run_scan") as scan,
        patch("pydoctor.cli.main._output"),
        patch("pydoctor.cli.main._exit_code", return_value=0),
    ):
        result = runner.invoke(app, ["github", "https://github.com/x/y", "--path", str(tmp_path)])
    assert "isn't supported yet" in result.output
    scan.assert_called_once()
