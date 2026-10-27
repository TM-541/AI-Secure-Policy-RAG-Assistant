"""
Layered prompt-injection defences for the policy assistant.

Input side:  normalise obfuscation (Unicode tricks, leetspeak, spaced letters,
             URL/ROT13/Base64/hex encodings), then scan every variant against
             injection, prompt-extraction, role-play and encoding-trick patterns.
Output side: detect system-prompt leakage via a secret canary token and
             phrase overlap with the confidential instructions.
"""

import base64
import binascii
import codecs
import re
import secrets
import unicodedata
from urllib.parse import unquote

from config import INJECTION_PATTERNS

# Zero-width and bidi control characters used to hide payloads.
INVISIBLE_CHARS = re.compile(r"[​-\u200F\u202A-\u202E⁠-⁤﻿­]")
LEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                            "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
# "i g n o r e" / "i.g.n.o.r.e" -> "ignore"
SPACED_LETTERS = re.compile(r"\b(?:\w[\s.\-_*]+){3,}\w\b")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){8,}\b")

_PATTERNS = INJECTION_PATTERNS + [
    # Instruction override
    r"\b(ignore|disregard|forget|override|bypass|overwrite)\b\W+(?:\w+\W+){0,3}?"
    r"(previous|prior|above|earlier|preceding|your|system|initial|original)\b\W+(?:\w+\W+){0,2}?"
    r"(instructions?|rules?|guidelines?|prompts?|directives?|guardrails?|restrictions?|constraints?|programming)",
    r"\b(new|updated|real|actual|secret)\s+(instructions?|rules|task|directive)s?\s*[:\-]",
    # Prompt / configuration extraction
    r"\b(system|initial|original|hidden|secret|developer|pre-?)\s*(prompt|instructions?|message|directives?|configuration)",
    r"\byour\s+(instructions?|prompt|rules|guidelines|directives|configuration|programming|guardrails|context window)\b",
    r"\b(repeat|print|output|reveal|show|display|echo|dump|leak|recite|write out|copy|tell me)\b.{0,40}"
    r"\b(above|verbatim|word for word|preceding|before this|the beginning|first (message|line|words))\b",
    r"\bstart(ing)?\s+(with|from)\s*[\"'“‘]",
    r"\byou are an?\s+(company|employee|policy)\b",
    r"\bwhat (were|are) you (told|instructed|programmed)\b",
    r"\b(first|last|opening|previous)\s+(line|lines|words?|sentences?|paragraph|message)\s+(of|in)\s+"
    r"(your|the (system|initial|above|previous|conversation))\b",
    # Role-play / jailbreak personas
    r"\b(you are now|from now on,? you|pretend (to be|you are|you're)|act as (if|though)|roleplay|role-play|jailbreak)\b",
    r"\bact as (an? )?(ai|assistant|chatbot|model|dan|hacker|unrestricted|unfiltered)\b",
    r"\b(dan mode|developer mode|god mode|do anything now|unfiltered|uncensored|no restrictions|without (any )?restrictions)\b",
    # Fake chat-template / role markers
    r"</?(system|instruction|prompt|admin|assistant|user|context)>",
    r"\[/?(inst|system)\]|<<\s*/?sys\s*>>|<\|im_(start|end)\|>|###\s*(system|instruction)",
    r"(^|\n)\s*(system|assistant)\s*:",
    # Encoding / transformation tricks
    r"\b(base\s?64|rot\s?-?13|hexadecimal|hex[\s-]?encoded|caesar cipher|morse code|binary code|ascii codes?)\b",
    r"\b(decode|encode|decrypt|deobfuscate|unscramble)\b",
    r"\b(translate|summari[sz]e|paraphrase|rewrite)\b.{0,30}\b(above|previous|preceding|your instructions|everything)\b",
    r"\b(reverse|backwards)\b.{0,20}\b(text|string|words|order)\b",
    r"\b(repeat after me|say exactly|respond only with|reply only with)\b",
]
INJECTION_REGEX = re.compile("|".join(f"(?:{p})" for p in _PATTERNS), re.IGNORECASE)


def _decode_blobs(text):
    """Return decodings of Base64/hex runs that turn out to be readable text."""
    decoded = []
    for blob in BASE64_BLOB.findall(text):
        padded = blob + "=" * (-len(blob) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                candidate = decoder(padded).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if _is_readable(candidate):
                decoded.append(candidate)
                break
    for blob in HEX_BLOB.findall(text):
        try:
            candidate = bytes.fromhex(re.sub(r"[\s:]", "", blob)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_readable(candidate):
            decoded.append(candidate)
    return decoded


def _is_readable(text):
    if len(text) < 6:
        return False
    printable = sum(ch.isprintable() and ord(ch) < 0x2000 for ch in text)
    letters = sum(ch.isalpha() or ch == " " for ch in text)
    return printable / len(text) > 0.9 and letters / len(text) > 0.6


def normalize(text):
    """Canonical form: NFKC (folds full-width/stylised letters), no invisibles, single spaces."""
    text = unicodedata.normalize("NFKC", text)
    text = INVISIBLE_CHARS.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def scan_variants(text):
    """All decodings an attacker might rely on the model to perform."""
    base = normalize(text)
    variants = {base, base.lower().translate(LEET_TABLE)}
    variants.add(SPACED_LETTERS.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group()), base))
    try:
        variants.add(unquote(base))
    except Exception:
        pass
    variants.add(codecs.decode(base, "rot_13"))
    variants.update(normalize(d) for d in _decode_blobs(base))
    return variants


def check_input(text):
    """Return (allowed, reason)."""
    if _decode_blobs(normalize(text)):
        return False, "Encoded payload detected."
    for variant in scan_variants(text):
        if INJECTION_REGEX.search(variant):
            return False, "Prompt injection pattern detected."
    return True, "ok"


def contains_injection(text):
    """Lighter check for retrieved document text (no encoding heuristics)."""
    return bool(INJECTION_REGEX.search(normalize(text)))


class LeakDetector:
    """Flags answers that reproduce the confidential instructions."""

    SHINGLE = 5

    def __init__(self):
        self.canary = secrets.token_hex(8)
        self._shingles = set()

    def protect(self, text):
        """Register confidential text whose reproduction counts as a leak."""
        self._shingles |= self._make_shingles(text)

    def _make_shingles(self, text):
        words = re.findall(r"[a-z0-9]+", normalize(text).lower())
        return {" ".join(words[i:i + self.SHINGLE]) for i in range(len(words) - self.SHINGLE + 1)}

    def is_leak(self, answer):
        if self.canary in answer:
            return True
        return len(self._make_shingles(answer) & self._shingles) >= 2
