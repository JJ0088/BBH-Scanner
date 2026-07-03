"""Interfaccia notifiche + implementazione no-op (default se non configurato)."""

from __future__ import annotations

from typing import Protocol


class Notifier(Protocol):
    def send(self, text: str) -> bool:
        ...


class NullNotifier:
    """Non invia nulla; utile se le notifiche non sono configurate o nei test."""

    def send(self, text: str) -> bool:  # noqa: D401
        return False
