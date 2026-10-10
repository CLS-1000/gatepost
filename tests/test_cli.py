import json

from gatepost.cli import main


def set_env(monkeypatch, comm_env, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    for k, v in comm_env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("ELEVATED_THRESHOLD", raising=False)


def test_brief_writes_expected_output(
    monkeypatch, comm_env, tmp_path, fixtures_dir, capsys
) -> None:
    set_env(monkeypatch, comm_env, tmp_path)
    out = tmp_path / "out" / "brief.md"
    code = main(
        [
            "brief",
            "--date",
            "2026-04-12",
            "--input",
            str(fixtures_dir / "signals_low_confidence.json"),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    assert (
        out.read_text() == (fixtures_dir / "expected_brief_2026-04-12.md").read_text()
    )
    assert "elevated=0" in capsys.readouterr().out


def test_missing_config_fails(monkeypatch, tmp_path, fixtures_dir, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    for k in ("COMM_TONE", "COMM_LANGUAGE", "COMM_SOURCE_TYPE", "COMM_FORMAT"):
        monkeypatch.delenv(k, raising=False)
    code = main(
        [
            "brief",
            "--date",
            "2026-04-12",
            "--input",
            str(fixtures_dir / "signals_low_confidence.json"),
            "--output",
            str(tmp_path / "b.md"),
        ]
    )
    assert code == 1
    assert "COMM_TONE" in capsys.readouterr().err
    assert not (tmp_path / "b.md").exists()


def test_bad_input_fails(monkeypatch, comm_env, tmp_path) -> None:
    set_env(monkeypatch, comm_env, tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"id": "a"}]))
    args = ["brief", "--date", "2026-04-12", "--output", str(tmp_path / "b.md")]
    assert main([*args, "--input", str(bad)]) == 1
    assert main([*args, "--input", str(tmp_path / "nope.json")]) == 1
