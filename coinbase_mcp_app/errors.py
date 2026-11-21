"""Structured, privacy-preserving application errors."""
from __future__ import annotations


class AppError(Exception):
    def __init__(self, code: str, message: str, action: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.action = action
        self.exit_code = exit_code
