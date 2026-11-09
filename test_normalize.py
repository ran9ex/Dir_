import unicodedata

from normalize import normalize, find_digit_runs, replace_spans


def test_constants_are_the_characters_we_think_they_are():
    # Guards against an editor silently swapping look-alike characters in the source file.
    import normalize as m
    assert m._TATWEEL == "ـ"
    assert m._LETTER_FOLD["أ"] == "ا"   # alef hamza above -> alef
    assert m._LETTER_FOLD["ى"] == "ي"   # alef maqsura -> yeh


def test_arabic_indic_digits():
    n = normalize("١٠٨٣٤٥٦٧٨٩")
    assert n.text == "1083456789"
    assert n.stats["digits_converted"] == 10


def test_persian_and_fullwidth_digits():
    assert normalize("۱۰۸۳").text == "1083"          # Persian
    assert normalize("１０８３").text == "1083"          # fullwidth


def test_ascii_digits_not_counted_as_converted():
    n = normalize("1083")
    assert n.text == "1083"
    assert n.stats["digits_converted"] == 0


def test_zero_width_chars_removed_and_counted():
    n = normalize("10​83‍45﻿")
    assert n.text == "108345"
    assert n.stats["invisible_removed"] == 3


def test_unicode_tag_characters_removed():
    # "Tag" characters (U+E0000 block) are invisible and can smuggle hidden instructions.
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "ignore")
    n = normalize("hello" + hidden)
    assert n.text == "hello"
    assert n.stats["invisible_removed"] == len("ignore")


def test_diacritics_and_tatweel_removed():
    # تَجَـاهَلْ  (with fatha, jeem, tatweel, sukun)
    s = "تَجَـاهَلْ"
    n = normalize(s)
    assert n.text == "تجاهل"                       # تجاهل
    assert n.stats["tatweel_removed"] == 1
    assert n.stats["marks_removed"] == 4


def test_letter_folding_optional():
    s = "أحمد إبراهيم"  # أحمد إبراهيم
    assert normalize(s).text == "احمد ابراهيم"
    assert normalize(s, fold_letters=False).text == s


def test_presentation_form_ligature_expands_with_valid_offsets():
    n = normalize("ﻻ")            # lam-alef ligature -> two letters
    assert n.text == "لا"
    assert n.offsets == [0, 0]
    assert n.span_to_original(0, 2) == (0, 1)


def test_offsets_are_consistent():
    s = "رقم ١٠​٨٣ تَم"
    n = normalize(s)
    assert len(n.offsets) == len(n.text)
    assert n.offsets == sorted(n.offsets)
    assert all(0 <= o < len(s) for o in n.offsets)


def test_idempotent():
    s = "هويتي ١٠​٨٣-٤٥٦ أحمد"
    once = normalize(s).text
    assert normalize(once).text == once


def test_empty_string():
    n = normalize("")
    assert n.text == "" and n.offsets == []
    assert find_digit_runs(n) == []


def test_digit_run_arabic_digits_with_dashes():
    s = "رقم هويتي ١٠٨٣-٤٥٦-٧٨٩٠ شكرا"
    runs = find_digit_runs(normalize(s))
    assert len(runs) == 1
    r = runs[0]
    assert r.digits == "10834567890"
    assert r.text == "١٠٨٣-٤٥٦-٧٨٩٠"


def test_digit_run_with_hidden_chars_and_spaces():
    s = "tel: 0 5 5​1 2 3 4 5 6 7 end"
    runs = find_digit_runs(normalize(s))
    assert [r.digits for r in runs] == ["0551234567"]
    assert s[runs[0].start:runs[0].end] == runs[0].text
    assert runs[0].text.startswith("0") and runs[0].text.endswith("7")


def test_short_numbers_ignored():
    s = "عمري 25 سنة"                  # عمري 25 سنة
    assert find_digit_runs(normalize(s)) == []


def test_two_separate_numbers_found():
    s = "id 1083456789 and phone 0551234567"
    runs = find_digit_runs(normalize(s))
    assert [r.digits for r in runs] == ["1083456789", "0551234567"]


def test_newline_does_not_join_numbers():
    s = "1083456789\n0551234567"
    runs = find_digit_runs(normalize(s))
    assert len(runs) == 2


def test_end_to_end_masking_uses_original_spans():
    # Fake ID typed with Arabic digits and a hidden character inside.
    s = "هويتي ١٠٨٣​٤٥٦٧٨٩ شكرا"
    n = normalize(s)
    runs = find_digit_runs(n)
    assert len(runs) == 1
    masked = replace_spans(s, [(r.start, r.end, "[ID_1]") for r in runs])
    assert masked == "هويتي [ID_1] شكرا"
    assert "​" not in masked


def test_replace_spans_rejects_overlap():
    import pytest
    with pytest.raises(ValueError):
        replace_spans("abcdef", [(0, 4, "X"), (2, 5, "Y")])
