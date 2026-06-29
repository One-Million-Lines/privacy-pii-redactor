"""
spaCy-based Named Entity Recognition (NER) detector.

Wraps spaCy's NLP pipeline to extract named entities (persons, organisations,
locations, etc.) from text. spaCy is an optional dependency — if not installed
this detector logs a single warning and returns ``[]`` for every call.

spaCy NE label → normalized entity type mapping is defined in
``_SPACY_TO_NORMALIZED``. Labels not present in the map are passed through
upper-cased.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from pii_redactor.models import DetectedEntity

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# spaCy NE label → normalized entity type mapping
# ──────────────────────────────────────────────────────────────────────────────

_SPACY_TO_NORMALIZED: dict[str, str] = {
    # English (en_core_web_*)
    "PERSON": "PERSON",
    "PER": "PERSON",   # multilingual models use PER
    "ORG": "ORGANIZATION",
    "GPE": "LOCATION",  # geo-political entity
    "LOC": "LOCATION",
    "FAC": "LOCATION",  # facility
    "PRODUCT": "PRODUCT",
    "EVENT": "EVENT",
    "WORK_OF_ART": "WORK_OF_ART",
    "LAW": "LAW",
    "LANGUAGE": "LANGUAGE",
    "DATE": "DATE_OF_BIRTH",
    "TIME": "TIME",
    "PERCENT": "PERCENT",
    "MONEY": "MONEY",
    "QUANTITY": "QUANTITY",
    "ORDINAL": "ORDINAL",
    "CARDINAL": "CARDINAL",
    "NORP": "NRP",   # nationalities, religious/political groups
    "MISC": "MISC",  # German/multilingual models
}

# Preferred model names per language (first available wins)
_MODELS_BY_LANG: dict[str, list[str]] = {
    "en": ["en_core_web_sm", "en_core_web_md", "en_core_web_lg"],
    "de": ["de_core_news_sm", "de_core_news_md"],
    "fr": ["fr_core_news_sm", "fr_core_news_md"],
    "es": ["es_core_news_sm", "es_core_news_md"],
    "it": ["it_core_news_sm"],
    "pt": ["pt_core_news_sm"],
    "nl": ["nl_core_news_sm"],
    "zh": ["zh_core_web_sm"],
}


class SpacyDetector:
    """
    NER-based PII detector using spaCy.

    Loads a spaCy model for the configured language and runs named entity
    recognition on the input text. Entity labels are mapped from spaCy's
    scheme to the normalized entity types used across the pipeline.

    Gracefully handles missing spaCy installation and missing language models —
    both cases result in a ``None`` NLP engine and a logged warning.

    Args:
        language: ISO 639-1 language code used to select the spaCy model.

    Example::

        detector = SpacyDetector(language="en")
        entities = detector.detect("Barack Obama was born in Hawaii.")
    """

    def __init__(self, language: str = "en") -> None:
        self._language = language
        self._nlp: Any | None = self._load_model(language)

    # ── Initialisation ────────────────────────────────────────────────────────

    def _load_model(self, language: str) -> Any | None:
        """
        Attempt to load an appropriate spaCy model for *language*.

        Iterates through the preferred model list for the language and returns
        the first one that loads successfully. Falls back to ``en_core_web_sm``
        if the language is unknown or no model can be loaded.

        Args:
            language: ISO 639-1 language code.

        Returns:
            Loaded spaCy Language object, or ``None`` on failure.
        """
        try:
            import spacy  # type: ignore[import]
        except ImportError:
            logger.warning(
                "spaCy is not installed. spaCy-based detection is disabled. "
                "Install it with: pip install spacy && python -m spacy download en_core_web_sm"
            )
            return None

        candidates = _MODELS_BY_LANG.get(language, _MODELS_BY_LANG["en"])

        for model_name in candidates:
            try:
                nlp = spacy.load(model_name, disable=["parser", "lemmatizer"])
                logger.debug("Loaded spaCy model '%s' for language '%s'", model_name, language)
                return nlp
            except Exception:  # noqa: BLE001 — OSError or similar from spaCy
                continue

        logger.warning(
            "No spaCy model available for language '%s'. "
            "Falling back to English model if available.",
            language,
        )
        for fallback in _MODELS_BY_LANG["en"]:
            try:
                import spacy  # type: ignore[import]

                nlp = spacy.load(fallback, disable=["parser", "lemmatizer"])
                logger.debug("Loaded fallback spaCy model '%s'", fallback)
                return nlp
            except Exception:  # noqa: BLE001
                continue

        logger.warning(
            "No spaCy model could be loaded. spaCy detection is disabled. "
            "Run: python -m spacy download en_core_web_sm"
        )
        return None

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """True if a spaCy model was loaded successfully."""
        return self._nlp is not None

    def detect(self, text: str, language: str | None = None) -> list[DetectedEntity]:
        """
        Run spaCy NER on *text* and return normalised detected entities.

        If no spaCy model is available, returns an empty list immediately.

        Args:
            text: Input text to analyse.
            language: ISO 639-1 language override. When different from the
                instance language a new model may need to be loaded; currently
                the instance model is reused regardless of language.

        Returns:
            List of :class:`~pii_redactor.models.DetectedEntity` with
            ``source="spacy"``.
        """
        if self._nlp is None or not text or not text.strip():
            return []

        try:
            doc = self._nlp(text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("spaCy NER failed: %s", exc)
            return []

        entities: list[DetectedEntity] = []
        for ent in doc.ents:
            normalized_type = _SPACY_TO_NORMALIZED.get(ent.label_, ent.label_.upper())
            # Use spaCy's built-in confidence if available (newer models expose it)
            confidence = 0.75  # default heuristic confidence for spaCy NER

            entities.append(
                DetectedEntity(
                    entity_type=normalized_type,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=confidence,
                    source="spacy",
                )
            )

        return entities
