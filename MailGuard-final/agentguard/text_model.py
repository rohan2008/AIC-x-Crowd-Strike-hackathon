"""Portable TF-IDF logistic model inference; training libraries are not imported here."""
import html
import math
import re
import unicodedata
from collections import Counter


def normalize(text):
    text = unicodedata.normalize('NFKC', html.unescape(text)).lower()
    return ' '.join(''.join(c for c in text if unicodedata.category(c) != 'Cf').split())


def features(text):
    text = normalize(text)[:24000]
    words = re.findall(r'\b\w+\b', text)
    tokens = ['w:' + w for w in words]
    tokens += ['b:' + a + ' ' + b for a, b in zip(words, words[1:])]
    for word in words:
        padded = ' ' + word + ' '
        for n in (3, 4, 5):
            tokens.extend('c:' + padded[i:i+n] for i in range(len(padded)-n+1))
    return tokens


def score(text, model):
    counts = Counter(features(text))
    known = {k: (1 + math.log(v)) * model['terms'][k][0] for k, v in counts.items() if k in model['terms']}
    # Abstain on inputs with no usable lexical evidence, regardless of intercept.
    if len([k for k in known if k.startswith('w:')]) < 3:
        return None
    norm = math.sqrt(sum(v*v for v in known.values()))
    margin = model['bias'] + sum(v * model['terms'][k][1] / norm for k, v in known.items())
    return 1 / (1 + math.exp(-max(-40, min(40, margin))))


def document_score(text, model):
    # Include the whole document plus overlapping windows; evaluate this exact path.
    words = normalize(text).split()
    chunks = [text]
    if len(words) > 160:
        chunks += [' '.join(words[i:i+160]) for i in range(0, len(words), 120)]
    values = [value for chunk in chunks if (value := score(chunk, model)) is not None]
    return max(values) if values else None
