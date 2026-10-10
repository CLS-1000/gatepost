"""Typed data models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Signal:
    id: str
    source: str
    category: str
    confidence: float
    summary: str
    timestamp: str


@dataclass(frozen=True)
class Communication:
    tone: str
    language: str
    source_type: str
    format: str


@dataclass(frozen=True)
class Config:
    communication: Communication
    elevated_threshold: float = 0.70
