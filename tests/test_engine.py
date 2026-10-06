import pytest
from app import engine
from app.samples import S

@pytest.mark.parametrize("scam,text", S)
def test_labelled_samples(scam, text):
    lvl = engine.analyze(text).level
    assert (lvl != "low") if scam else (lvl == "low")

def test_google_form_is_a_tool_not_an_identity():
    r = engine.analyze("Fill this Google Form to register for the workshop: https://forms.gle/x")
    assert r.level == "low" and not any(f.id == "impersonation" for f in r.flags)

def test_negated_otp_not_flagged():
    assert not any(f.id == "cred" for f in engine.analyze("Do not share your OTP with anyone.").flags)

def test_spans_match_original_text():
    t = "Urgent!\u200b Pay Rs. 500 registration fee"
    for f in engine.analyze(t).flags:
        for a, b in f.spans: assert t[a:b].strip()

@pytest.mark.parametrize("t", ["", " ", "😀" * 500, "\u200b" * 50, "http://" , "a@b", "x" * 6000])
def test_never_crashes(t):
    engine.analyze(t)
