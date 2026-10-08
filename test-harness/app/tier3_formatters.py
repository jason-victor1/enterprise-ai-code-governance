"""
Tier 3: Presentation and Localized Utilities (Leaf Node).
Eligible for automated merge upon passing baseline tests with zero Tier 1/2 dependencies.
"""
import re


class OutputFormatter:
    """Pure string and payload formatting utilities."""

    @staticmethod
    def sanitize_audit_log(message: str) -> str:
        """Strips newlines and carriage returns to prevent log injection."""
        return message.replace("\r", "").replace("\n", " ").strip()

    @staticmethod
    def mask_sensitive_token(token: str, visible_suffix_len: int = 4) -> str:
        """Masks high-entropy tokens while preserving a trailing verification suffix."""
        if len(token) <= visible_suffix_len:
            return "*" * len(token)
        masked_portion = "*" * (len(token) - visible_suffix_len)
        return masked_portion + token[-visible_suffix_len:]

    @staticmethod
    def slugify(text: str) -> str:
        """Formats string to URL-safe alphanumeric kebab-case."""
        text = text.lower().strip()
        text = re.sub(r"[^\w\s-]", "", text)
        return re.sub(r"[-\s]+", "-", text)
