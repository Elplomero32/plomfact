"""Herramienta de operación con la plantilla oficial vacía: todo queda bloqueado."""

import shutil

from plomfact_ecf.cli import main

from conftest import ROOT


def test_plantilla_vacia_reporta_pendientes_y_bloquea_transmision(tmp_path, capsys):
    shutil.copy(ROOT / "config" / "dgii_spec.example.toml", tmp_path / "dgii_spec.toml")
    cfg = (ROOT / "config" / "settings.example.toml").read_text()
    (tmp_path / "settings.toml").write_text(cfg.replace('rnc_emisor = ""', 'rnc_emisor = "101000001"'))
    assert main(["--config", str(tmp_path / "settings.toml"), "verificar-spec"]) == 1
    assert "endpoints.recepcion_ecf" in capsys.readouterr().out
    assert main(["--config", str(tmp_path / "settings.toml"), "transmitir"]) == 2
    assert "sin verificar" in capsys.readouterr().err
    assert main(["--config", str(tmp_path / "settings.toml"), "integridad"]) == 0
