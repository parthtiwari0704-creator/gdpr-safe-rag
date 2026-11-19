"""GDPR-safe document assistant: a privacy-first RAG chatbot."""
from .pipeline import GDPRAssistant
from .pii import PIIDetector, redact

__all__ = ["GDPRAssistant", "PIIDetector", "redact"]
__version__ = "1.0.0"
