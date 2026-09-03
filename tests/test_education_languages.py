import pytest
from intelligence.education.languages import Formality, LanguagePreference, ScriptPreference, SpokenLanguage


def test_language_dialect_script_retained():
    punjabi = LanguagePreference(SpokenLanguage.PUNJABI, SpokenLanguage.PUNJABI, ScriptPreference.GURMUKHI, "Malwai", Formality.FRIENDLY)
    shahmukhi = LanguagePreference(SpokenLanguage.PUNJABI, SpokenLanguage.PUNJABI, ScriptPreference.SHAHMUKHI, "Majhi", Formality.PROFESSIONAL)
    yorkshire = LanguagePreference(SpokenLanguage.ENGLISH, SpokenLanguage.ENGLISH, ScriptPreference.LATIN, "Yorkshire", Formality.PROFESSIONAL)
    spoken_punjabi_written_english = LanguagePreference(
        SpokenLanguage.PUNJABI, SpokenLanguage.ENGLISH, ScriptPreference.LATIN, "Malwai", Formality.FRIENDLY
    )
    spoken_english_written_punjabi = LanguagePreference(
        SpokenLanguage.ENGLISH, SpokenLanguage.PUNJABI, ScriptPreference.GURMUKHI, "standard", Formality.PROFESSIONAL
    )
    assert punjabi.script is ScriptPreference.GURMUKHI
    assert shahmukhi.script is ScriptPreference.SHAHMUKHI
    assert yorkshire.dialect == "Yorkshire"
    assert spoken_punjabi_written_english.script is ScriptPreference.LATIN
    assert spoken_english_written_punjabi.written is SpokenLanguage.PUNJABI
    with pytest.raises(ValueError):
        LanguagePreference(SpokenLanguage.ENGLISH, SpokenLanguage.PUNJABI, ScriptPreference.LATIN, "Malwai", Formality.FRIENDLY)
