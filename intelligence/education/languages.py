from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SpokenLanguage(str, Enum):
    ENGLISH = "english"
    PUNJABI = "punjabi"
    HINDI = "hindi"
    URDU = "urdu"
    OTHER = "other"


class ScriptPreference(str, Enum):
    LATIN = "latin"
    GURMUKHI = "gurmukhi"
    SHAHMUKHI = "shahmukhi"
    DEVANAGARI = "devanagari"
    ARABIC = "arabic"


class Formality(str, Enum):
    FRIENDLY = "friendly"
    PROFESSIONAL = "professional"
    FORMAL = "formal"


@dataclass(frozen=True)
class LanguagePreference:
    spoken: SpokenLanguage
    written: SpokenLanguage
    script: ScriptPreference
    dialect: str
    formality: Formality
    preferred_terminology: str = ""
    translation_required: bool = False
    pronunciation_notes: str = ""

    def __post_init__(self) -> None:
        if self.written is SpokenLanguage.PUNJABI and self.script not in {
            ScriptPreference.GURMUKHI,
            ScriptPreference.SHAHMUKHI,
        }:
            raise ValueError("written Punjabi requires Gurmukhi or Shahmukhi script preference")
