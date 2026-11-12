"""Adaptadores para servicios externos."""

from ai_soc.adapters.database import DatabaseManager
from ai_soc.adapters.geo import GeoIPProvider, HTTPXGeoIPAdapter

__all__ = ["DatabaseManager", "GeoIPProvider", "HTTPXGeoIPAdapter"]
