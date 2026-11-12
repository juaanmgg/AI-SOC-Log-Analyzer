"""Contratos de datos del dominio SOC."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field
from pydantic.networks import IPvAnyAddress


class SeverityEnum(str, Enum):
    """Severidad normalizada de una amenaza."""

    BAJA = "Baja"
    MEDIA = "Media"
    ALTA = "Alta"
    CRITICA = "Crítica"


class ThreatItem(BaseModel):
    """Amenaza detectada y validada."""

    model_config = ConfigDict(extra="forbid")

    ip: IPvAnyAddress
    tipo: str = Field(min_length=1)
    severidad: SeverityEnum


class ThreatReport(BaseModel):
    """Informe estructurado de amenazas."""

    model_config = ConfigDict(extra="forbid")

    amenazas: list[ThreatItem]


class DatabaseRecord(BaseModel):
    """Registro persistido de una amenaza."""

    model_config = ConfigDict(extra="forbid")

    id: int | None = None
    ip: IPvAnyAddress
    pais: str = Field(min_length=1)
    tipo: str = Field(min_length=1)
    severidad: SeverityEnum
    expira_en: datetime
    activo: bool
