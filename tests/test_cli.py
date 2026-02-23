import pytest
from click.testing import CliRunner
from valkyrie.cli.main import cli
import tempfile
import os

def test_analyze_help():
    runner = CliRunner()
    result = runner.invoke(cli, ['analyze', '--help'])
    assert result.exit_code == 0
    assert '--file' in result.output
    assert '--mode' in result.output

def test_analyze_command():
    runner = CliRunner()
    # Create a dummy file to pass the file existence check
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file_name = tmp_file.name
    
    try:
        result = runner.invoke(cli, ['analyze', '--file', tmp_file_name, '--mode', 'static'])
        assert result.exit_code == 0
        assert "Starting static analysis" in result.output
        assert "Analysis complete" in result.output
    finally:
        os.remove(tmp_file_name)
