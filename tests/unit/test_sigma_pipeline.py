"""Tests hors-ligne : le pipeline mappe les champs Sigma vers le schéma Wazuh."""

import subprocess
import textwrap

PIPELINE = "detections/pipelines/wazuh-windows.yml"


def _convert(rule_path):
    proc = subprocess.run(
        ["sigma", "convert", "-t", "opensearch_lucene", "-p", PIPELINE, str(rule_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def test_process_creation_maps_to_wazuh_fields_and_sysmon_channel(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text(
        textwrap.dedent("""
        title: probe
        id: 11111111-1111-4111-8111-111111111111
        status: experimental
        logsource:
          category: process_creation
          product: windows
        detection:
          sel:
            CommandLine|contains: 'IEX'
          condition: sel
        level: low
    """)
    )
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.commandLine" in out
    assert "Microsoft-Windows-Sysmon/Operational" in out
    assert "data.win.system.eventID" in out


def test_ps_script_maps_to_scriptblock_and_powershell_channel(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text(
        textwrap.dedent("""
        title: probe
        id: 22222222-2222-4222-8222-222222222222
        status: experimental
        logsource:
          category: ps_script
          product: windows
        detection:
          sel:
            ScriptBlockText|contains: 'IEX('
          condition: sel
        level: low
    """)
    )
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.scriptBlockText" in out
    assert "Microsoft-Windows-PowerShell/Operational" in out


def test_rule_a_encoded_command_valid_and_maps_fields():
    rule = "detections/windows/t1059.001_powershell_encoded_command.yml"
    check = subprocess.run(["sigma", "check", rule], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.commandLine" in out
    assert "data.win.eventdata.image" in out
    assert "-e" in out
    assert "-Enc" in out


def test_rule_b_valid_and_contains_scriptblock_terms():
    rule = "detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml"
    check = subprocess.run(["sigma", "check", rule], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.scriptBlockText" in out
    assert "Microsoft-Windows-PowerShell/Operational" in out
    for term in ["Invoke-Expression", "DownloadString", "Net.WebClient"]:
        assert term in out
