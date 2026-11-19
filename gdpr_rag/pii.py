"""PII detection and pseudonymisation.

Detects personal data in free text and replaces every match with a stable
placeholder such as ``[PERSON_1]`` or ``[IBAN_3]``. Detection is layered:

* Structured identifiers with checksum validation, so random numbers are not
  over-redacted: IBAN (ISO 13616 mod-97), payment cards (Luhn) and Dutch BSN
  (11-proef).
* Pattern-based identifiers: e-mail, phone, IP address, Dutch postcode,
  street address, dates of birth (context based).
* Person names: spaCy NER when a model is installed, plus rule-based
  detection (titles like Mr./Dhr./Mevr., labels like "Account holder:",
  greetings like "Dear ..."). Every name found is then redacted everywhere it
  re-appears in the document.

The detector never needs network access, so it is safe to run before any data
leaves the machine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Entity:
    type: str
    start: int
    end: int
    value: str
    priority: int = 0  # higher wins on overlap

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class RedactionResult:
    text: str                      # redacted text
    entities: list[Entity]         # what was found (with original values)
    replacements: dict[str, str]   # token -> original value (stays local!)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entities:
            out[e.type] = out.get(e.type, 0) + 1
        return out


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #

IBAN_LENGTHS = {
    "NL": 18, "DE": 22, "BE": 16, "FR": 27, "GB": 22, "ES": 24, "IT": 27,
    "LU": 20, "IE": 22, "AT": 20, "CH": 21, "PT": 25, "PL": 28, "SE": 24,
    "DK": 18, "FI": 18, "NO": 15, "AE": 23, "SA": 24, "CZ": 24, "GR": 27,
}


def iban_is_valid(raw: str) -> bool:
    iban = re.sub(r"\s+", "", raw).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", iban):
        return False
    expected = IBAN_LENGTHS.get(iban[:2])
    if expected and len(iban) != expected:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def luhn_is_valid(raw: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", raw)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def bsn_is_valid(raw: str) -> bool:
    """Dutch citizen service number, 11-proef."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9 or digits == "000000000":
        return False
    weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
    return sum(int(d) * w for d, w in zip(digits, weights)) % 11 == 0


# Verhoeff checksum, used by UIDAI for the last digit of an Aadhaar number.
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_is_valid(number: str) -> bool:
    c = 0
    for i, d in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(d)]]
    return c == 0


def aadhaar_is_valid(raw: str) -> bool:
    """12 digits, cannot start with 0 or 1, Verhoeff check digit."""
    digits = re.sub(r"[\s-]", "", raw)
    return bool(re.fullmatch(r"[2-9]\d{11}", digits)) and verhoeff_is_valid(digits)


# --------------------------------------------------------------------------- #
# Regex patterns
# --------------------------------------------------------------------------- #

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
BSN_RE = re.compile(r"\b\d{9}\b|\b\d{4}\.\d{2}\.\d{3}\b")
PHONE_RE = re.compile(
    r"(?<![\w+])(?:"
    r"\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,5}){2,4}"   # international
    r"|0\d{1,3}[ -]?\d{6,8}"                                # 06-12345678, 020 1234567
    r"|0\d{1,3}[ -]\d{3,4}[ -]\d{3,4}"                      # 020 123 4567
    r")(?!\w)"
)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
POSTCODE_NL_RE = re.compile(r"\b[1-9]\d{3}[ ]?(?!SA|SD|SS)[A-Z]{2}\b")
STREET_SUFFIX = r"(?:straat|gracht|laan|weg|plein|kade|singel|dijk|dreef|hof|pad|steeg|markt)"
ADDRESS_RE = re.compile(
    r"\b[A-Z][a-zà-ÿ]+" + STREET_SUFFIX + r"[ ]\d{1,4}[A-Za-z]?(?:[-/ ]\d{1,4})?\b"
    r"|\b\d{1,5}[ ](?:[A-Z][a-z]+[ ]){1,3}(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Lane|Drive|Boulevard)\b"
)
DATE = r"(?:\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2}[ ](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[ ]\d{4})"
DOB_RE = re.compile(
    r"(?i:date of birth|birth ?date|born(?: on)?|d\.?o\.?b\.?|geboortedatum|geboren(?: op)?)\s*:?\s*(" + DATE + r")"
)

# "Address: <anything>" — the whole value of an address field is personal data.
ADDRESS_LINE_RE = re.compile(
    r"(?im)^[ \t]*(?:address|residential address|permanent address|current address|"
    r"correspondence address|communication address|adres)[ \t]*:[ \t]*(.+?)[ \t]*$"
)

def _looks_like_address(value: str) -> bool:
    """A real address has a house number or several words (not just a leftover city name)."""
    return bool(re.search(r"\d", value)) or len(re.findall(r"[A-Za-z]{2,}", value)) >= 3


# India --------------------------------------------------------------------
AADHAAR_RE = re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])")
# PAN: 5 letters, 4 digits, 1 letter; 4th letter = holder type (P = person, C = company ...)
PAN_RE = re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")
GSTIN_RE = re.compile(r"\b\d{2}[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")
# UPI ID: handle@psp (no dot after @, which separates it from an e-mail address)
UPI_RE = re.compile(r"(?<![\w.@])[A-Za-z0-9][\w.\-]{1,63}@(?:ok)?[a-z]{2,20}(?![\w.@])")
IN_MOBILE_RE = re.compile(r"(?<![\d+])(?:(?:\+91|0091|91)[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
ACCOUNT_RE = re.compile(
    r"(?i:a/c|acct|account|bank account|savings account|current account|loan account|beneficiary account)"
    r"(?:\s*(?:no\.?|number|#))?[ \t]*[:\-]?[ \t]*(\d[\d ]{7,20}\d)"
)
PINCODE_RE = re.compile(r"(?i:pin(?:[ ]?code)?|pincode)[ \t]*[:\-]?[ \t]*([1-9]\d{2}[ ]?\d{3})\b"
                        r"|(?<=[A-Za-z][ ]-[ ])([1-9]\d{5})\b|(?<=[A-Za-z]-)([1-9]\d{5})\b")
PASSPORT_IN_RE = re.compile(r"(?i:passport(?:[ ]?(?:no\.?|number))?)[ \t]*[:\-]?[ \t]*([A-PR-WY][1-9]\d{6})\b")
VOTER_ID_RE = re.compile(r"(?i:voter[ ]?id|epic(?:[ ]?no\.?)?)[ \t]*[:\-]?[ \t]*([A-Z]{3}\d{7})\b")

# Person names --------------------------------------------------------------
_PARTICLES = r"(?:van|de|der|den|ter|ten|het|von|di|da|del|du|le|la|el|al|bin|ibn)"
_CAP = r"[A-Z][a-zà-ÿ'’\-]+"
NAME = _CAP + r"(?:[ ](?:" + _PARTICLES + r"[ ])*" + _CAP + r"){0,3}"
TITLE_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Sir|Madam|Dhr|Mevr|Mevrouw|Meneer|Mw|Ir|Drs|Shri|Smt|Sh|Kumari|Km|Sri|Srimati|Shrimati|S/o|D/o|W/o|C/o)\.?[ ]+((?:" + _PARTICLES + r"[ ])*" + NAME + r")"
)
LABEL_RE = re.compile(
    r"(?im)\b(?:name|full name|customer|client|account holder|holder|beneficiary|payee|payer|"
    r"applicant|co-applicant|employee|contact person|signed by|signature|prepared by|"
    r"rekeninghouder|naam|klant|begunstigde|aanvrager|borrower|co-borrower|guarantor|nominee|"
    r"customer name|father's name|mother's name|spouse name|complainant|account holder name|"
    r"relationship manager|branch manager|officer)[ \t]*:[ \t]*(" + NAME + r")"
)
GREETING_RE = re.compile(r"\b(?:Dear|Hi|Hello|Beste|Geachte)[ ]+(?:(?:Mr|Mrs|Ms|Dr|heer|mevrouw)\.?[ ]+)?(" + NAME + r")")
SIGNOFF_RE = re.compile(r"(?im)^(?:kind regards|best regards|regards|sincerely|met vriendelijke groet)[,]?\s*\n[ \t]*(" + NAME + r")[ \t]*$")

# Words that look like names at the start of a label but are not people.
_NOT_NAMES = {
    "Bank", "The", "Team", "Department", "Customer", "Client", "Service", "Support",
    "Compliance", "Unknown", "N/A", "None", "Not", "Mortgage", "Loan", "Account",
    "ING", "ABN", "AMRO", "Rabobank", "Insurance", "Credit", "Fraud", "Risk",
    "Mr", "Mrs", "Ms", "Miss", "Mx", "Dr", "Prof", "Sir", "Madam", "Dhr", "Mevr", "Mevrouw",
    "Meneer", "Mw", "Ir", "Drs", "Heer", "Shri", "Smt", "Sh", "Kumari", "Km", "Sri",
    "HDFC", "ICICI", "SBI", "Axis", "Kotak", "Paytm", "UPI", "NPCI", "RBI", "Branch",
}

STRICT_NAME_RE = re.compile(r"(?<![\w\[])" + _CAP + r"(?:[ ](?:" + _PARTICLES + r"[ ])*" + _CAP + r"){1,3}(?![\w\]])")
_STRICT_SKIP = {
    "What", "Who", "Why", "When", "Where", "Which", "How", "Is", "Does", "Did", "Can", "Show",
    "List", "Give", "Tell", "Summarise", "Summarize", "Explain", "Please", "EUR", "SEPA",
    "Germany", "Netherlands", "Nigeria", "Amsterdam", "Rotterdam", "Utrecht", "November",
    "October", "December", "January", "Know", "Your", "Investigations", "Case", "Status",
    "India", "Mumbai", "Delhi", "Bengaluru", "Bangalore", "Pune", "Noida", "Gurugram", "Chennai",
    "Hyderabad", "Kolkata", "Dubai", "KYC", "Re-KYC", "UPI", "RBI",
    "Will", "Has", "Have", "Had", "Was", "Were", "Are", "Do", "Should", "Could", "Would", "Find",
    "Check", "Get", "Did", "Has", "Whose", "Am", "Tell", "Me", "About", "Why",
}

# Optional spaCy NER ----------------------------------------------------------
_NLP = None
_NLP_TRIED = False


def _get_nlp():
    global _NLP, _NLP_TRIED
    if _NLP_TRIED:
        return _NLP
    _NLP_TRIED = True
    try:  # pragma: no cover - depends on optional install
        import spacy

        for model in ("en_core_web_sm", "nl_core_news_sm", "xx_ent_wiki_sm"):
            try:
                _NLP = spacy.load(model, disable=["parser", "lemmatizer"])
                break
            except OSError:
                continue
    except ImportError:
        _NLP = None
    return _NLP


def spacy_available() -> bool:
    return _get_nlp() is not None


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #

PRIORITY = {
    "EMAIL": 90, "GSTIN": 88, "IBAN": 85, "AADHAAR": 83, "CARD": 80, "PAN": 79, "UPI": 78,
    "ACCOUNT": 82, "PASSPORT": 76, "VOTER_ID": 76, "BSN": 75, "DOB": 70, "IP": 65,
    "PHONE": 60, "ADDRESS": 55, "ADDRESS_LINE": 56, "POSTCODE": 50, "PINCODE": 50, "PERSON": 40,
}

# Which identifier families to look for. "eu" = Netherlands/EU, "in" = India.
REGIONS = ("eu", "in")


class PIIDetector:
    def __init__(self, use_spacy: bool = True, extra_names: Iterable[str] = (), strict: bool = False,
                 regions: Iterable[str] = REGIONS):
        """strict=True also treats any run of 2+ capitalised words as a possible
        name. Used for questions and for the outgoing-prompt leak guard, where
        over-redacting is cheap and leaking is not."""
        self.use_spacy = use_spacy
        self.strict = strict
        self.regions = set(regions)
        self.extra_names = [n for n in extra_names if n.strip()]

    # -- individual detectors ------------------------------------------------
    def _regex(self, text: str, pattern: re.Pattern, etype: str, group: int = 0,
               validator: Callable[[str], bool] | None = None) -> list[Entity]:
        out = []
        for m in pattern.finditer(text):
            value = m.group(group)
            if not value:
                continue
            if validator and not validator(value):
                continue
            out.append(Entity(etype, m.start(group), m.end(group), value, PRIORITY[etype]))
        return out

    @staticmethod
    def _clean_name(name: str) -> str | None:
        name = re.sub(r"['’]s?$", "", name.strip())  # possessive: "Visser's" -> "Visser"
        words = name.split()
        while words and words[-1] in _NOT_NAMES:
            words.pop()
        if not words or words[0] in _NOT_NAMES:
            return None
        cleaned = " ".join(words)
        return cleaned if len(cleaned) >= 2 else None

    def _names(self, text: str) -> list[Entity]:
        found: list[Entity] = []
        for pattern in (TITLE_RE, LABEL_RE, GREETING_RE, SIGNOFF_RE):
            for m in pattern.finditer(text):
                cleaned = self._clean_name(m.group(1))
                if cleaned:
                    start = m.start(1)
                    found.append(Entity("PERSON", start, start + len(cleaned), cleaned, PRIORITY["PERSON"]))

        if self.strict:
            for m in STRICT_NAME_RE.finditer(text):
                words = m.group(0).split(" ")
                offset = m.start()
                while words and words[0] in _STRICT_SKIP:  # "Is Karel Peeters" -> "Karel Peeters"
                    offset += len(words.pop(0)) + 1
                cleaned = self._clean_name(" ".join(words)) if len(words) >= 2 else None
                if cleaned and any(k in cleaned for k in self.extra_names):
                    continue  # a known name is inside; the known-name pass handles it exactly
                if cleaned and not (set(cleaned.split()) & _STRICT_SKIP):
                    found.append(Entity("PERSON", offset, offset + len(cleaned), cleaned, PRIORITY["PERSON"] - 2))

        nlp = _get_nlp() if self.use_spacy else None
        if nlp is not None:  # pragma: no cover - optional
            for ent in nlp(text).ents:
                if ent.label_ in ("PERSON", "PER") and self._clean_name(ent.text):
                    found.append(Entity("PERSON", ent.start_char, ent.end_char, ent.text, PRIORITY["PERSON"] - 1))

        # Link "Mr. Bakker" / "Ms. Visser" to the full name "Thomas Bakker" so the
        # same person always gets the same placeholder.
        # Order: names in this document by first appearance, then names already in the vault.
        doc_full = sorted({e.value: e.start for e in sorted(found, key=lambda e: -e.start)
                           if len(e.value.split()) >= 2}.items(), key=lambda kv: kv[1])
        full_names = [n for n, _ in doc_full] + [n for n in self.extra_names if n not in dict(doc_full)]

        def _canonical(name: str) -> str:
            if len(name.split()) >= 2 and name in full_names:
                return name
            for full in full_names:
                if full != name and (full.endswith(" " + name) or full.lower().endswith(" " + name.lower())):
                    return full
            return name

        found = [Entity(e.type, e.start, e.end, _canonical(e.value), e.priority) for e in found]

        # Propagate: every distinct name is redacted wherever it re-appears.
        names = {e.value for e in found} | set(self.extra_names)
        for name in sorted(names, key=len, reverse=True):
            variants = {name}
            parts = name.split()
            if len(parts) >= 2:  # surname after a title elsewhere, e.g. "Mr. de Vries"
                surname = " ".join(parts[1:])
                for t in re.finditer(r"\b(?:Mr|Mrs|Ms|Dr|Dhr|Mevr|Mevrouw)\.?[ ]+(" + re.escape(surname) + r")\b", text):
                    found.append(Entity("PERSON", t.start(1), t.end(1), name, PRIORITY["PERSON"]))
            for v in variants:
                for m in re.finditer(r"(?<!\w)" + re.escape(v) + r"(?!\w)", text, flags=re.IGNORECASE):
                    found.append(Entity("PERSON", m.start(), m.end(), name, PRIORITY["PERSON"]))
        return found

    # -- public API ---------------------------------------------------------
    def detect(self, text: str) -> list[Entity]:
        candidates: list[Entity] = []
        candidates += self._regex(text, EMAIL_RE, "EMAIL")
        candidates += self._regex(text, IBAN_RE, "IBAN", validator=iban_is_valid)
        candidates += self._regex(text, CARD_RE, "CARD", validator=luhn_is_valid)
        candidates += self._regex(text, DOB_RE, "DOB", group=1)
        candidates += self._regex(text, IP_RE, "IP")
        candidates += [Entity("ADDRESS", e.start, e.end, e.value, PRIORITY["ADDRESS_LINE"])
                       for e in self._regex(text, ADDRESS_LINE_RE, "ADDRESS", group=1, validator=_looks_like_address)]
        candidates += self._regex(text, PHONE_RE, "PHONE",
                                  validator=lambda v: 9 <= len(re.sub(r"\D", "", v)) <= 15)
        if "eu" in self.regions:
            candidates += self._regex(text, BSN_RE, "BSN", validator=bsn_is_valid)
            candidates += self._regex(text, ADDRESS_RE, "ADDRESS")
            candidates += self._regex(text, POSTCODE_NL_RE, "POSTCODE")
        if "in" in self.regions:
            candidates += self._regex(text, AADHAAR_RE, "AADHAAR", validator=aadhaar_is_valid)
            candidates += self._regex(text, PAN_RE, "PAN")
            candidates += self._regex(text, GSTIN_RE, "GSTIN")
            candidates += self._regex(text, UPI_RE, "UPI")
            candidates += self._regex(text, IN_MOBILE_RE, "PHONE")
            candidates += self._regex(text, ACCOUNT_RE, "ACCOUNT", group=1)
            candidates += self._regex(text, PASSPORT_IN_RE, "PASSPORT", group=1)
            candidates += self._regex(text, VOTER_ID_RE, "VOTER_ID", group=1)
            for g in (1, 2, 3):
                candidates += [e for e in self._regex(text, PINCODE_RE, "PINCODE", group=g)]
        candidates += self._names(text)
        return self._resolve_overlaps(candidates)

    @staticmethod
    def _resolve_overlaps(entities: list[Entity]) -> list[Entity]:
        # Highest priority first, then longest; keep a span only if it doesn't
        # overlap anything already accepted.
        accepted: list[Entity] = []
        for e in sorted(entities, key=lambda x: (-x.priority, -x.length, x.start)):
            if all(e.end <= a.start or e.start >= a.end for a in accepted):
                accepted.append(e)
        return sorted(accepted, key=lambda x: x.start)

    def contains_pii(self, text: str) -> list[Entity]:
        """Return PII still present in text, ignoring our own placeholders."""
        stripped = PLACEHOLDER_RE.sub(lambda m: " " * len(m.group(0)), text)
        return self.detect(stripped)


# [PERSON_3] = known to the vault; [PERSON_Q1] = only seen in a question.
ENTITY_TYPES = ("PERSON", "EMAIL", "IBAN", "CARD", "BSN", "DOB", "IP", "PHONE", "ADDRESS", "POSTCODE",
                "AADHAAR", "PAN", "GSTIN", "UPI", "ACCOUNT", "PASSPORT", "VOTER_ID", "PINCODE")
PLACEHOLDER_RE = re.compile(r"\[(?:" + "|".join(ENTITY_TYPES) + r")_Q?\d+\]")


def normalise(etype: str, value: str) -> str:
    """Canonical form so the same identifier always gets the same token."""
    if etype in ("IBAN", "CARD", "BSN", "PHONE", "AADHAAR", "PAN", "GSTIN", "ACCOUNT",
                 "PASSPORT", "VOTER_ID", "PINCODE"):
        v = re.sub(r"[^A-Za-z0-9+]", "", value).upper()
        if etype == "PHONE" and v.startswith("+31"):
            v = "0" + v[3:]
        if etype == "PHONE" and re.fullmatch(r"(\+91|0091|91)[6-9]\d{9}", v):
            v = v[-10:]
        return v
    if etype == "UPI":
        return value.lower()
    if etype == "EMAIL":
        return value.lower()
    return re.sub(r"\s+", " ", value).strip()


class _LocalTokenizer:
    """Fallback token provider (no vault): consistent within one call."""

    def __init__(self) -> None:
        self.map: dict[tuple[str, str], str] = {}
        self.counters: dict[str, int] = {}

    def __call__(self, etype: str, value: str) -> str:
        key = (etype, normalise(etype, value))
        if key not in self.map:
            self.counters[etype] = self.counters.get(etype, 0) + 1
            self.map[key] = f"[{etype}_{self.counters[etype]}]"
        return self.map[key]


def redact(text: str, detector: PIIDetector | None = None,
           tokenizer: Callable[[str, str], str] | None = None) -> RedactionResult:
    detector = detector or PIIDetector()
    tokenizer = tokenizer or _LocalTokenizer()
    entities = detector.detect(text)
    pieces, last, replacements = [], 0, {}
    for e in entities:
        token = tokenizer(e.type, e.value)
        replacements[token] = e.value
        pieces.append(text[last:e.start])
        pieces.append(token)
        last = e.end
    pieces.append(text[last:])
    return RedactionResult("".join(pieces), entities, replacements)


def reidentify(text: str, lookup: Callable[[str], str | None]) -> str:
    """Swap placeholders back to real values (local only, authorised users)."""
    def _sub(m: re.Match) -> str:
        real = lookup(m.group(0))
        return real if real is not None else m.group(0)
    return PLACEHOLDER_RE.sub(_sub, text)
