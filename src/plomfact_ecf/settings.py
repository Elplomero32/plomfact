"""Configuración local del emisor (no contiene secretos)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .alerts import Umbrales
from .spec import Ambiente


@dataclass
class Settings:
    ambiente: Ambiente
    rnc_emisor: str
    razon_social: str
    base_datos: Path
    evidencias: Path
    spec: Path
    certificado: Path
    clave_env: str | None = None
    clave_archivo: Path | None = None
    xsd: dict[str, Path] = field(default_factory=dict)
    produccion_habilitada: bool = False
    umbrales: Umbrales = field(default_factory=Umbrales)

    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        p = Path(path)
        d = tomllib.loads(p.read_text("utf-8"))
        base = p.parent
        rel = lambda v: (base / v).resolve() if v else None  # noqa: E731
        u = d.get("umbrales", {})
        return cls(
            ambiente=Ambiente(d["ambiente"]),
            rnc_emisor=str(d["rnc_emisor"]),
            razon_social=d["razon_social"],
            base_datos=rel(d["base_datos"]),
            evidencias=rel(d["evidencias"]),
            spec=rel(d["spec"]),
            certificado=rel(d["certificado"]["archivo"]),
            clave_env=d["certificado"].get("clave_env"),
            clave_archivo=rel(d["certificado"].get("clave_archivo")),
            xsd={str(k): rel(v) for k, v in d.get("xsd", {}).items()},
            produccion_habilitada=bool(d.get("produccion_habilitada", False)),
            umbrales=Umbrales(
                certificado_dias=tuple(u.get("certificado_dias", (60, 15))),
                rango_dias=tuple(u.get("rango_dias", (30, 7))),
                rango_restantes=tuple(u.get("rango_restantes", (500, 50))),
            ),
        )
