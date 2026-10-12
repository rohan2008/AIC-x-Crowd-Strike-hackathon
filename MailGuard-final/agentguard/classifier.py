"""Experimental local text classifier. No network, execution, or delivery authority."""
import json
import math
import re
import base64
from collections import Counter
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).with_name('classifier_data')


def features(text):
    words = re.findall(r"[a-z]+(?:'[a-z]+)?", text.lower())
    return words + [' '.join(pair) for pair in zip(words, words[1:])]


def train(rows):
    counts = {label: Counter() for label in ('benign', 'suspicious')}
    documents = Counter()
    for row in rows:
        counts[row['label']].update(features(row['text']))
        documents[row['label']] += 1
    vocabulary = sorted(set(counts['benign']) | set(counts['suspicious']))
    totals = {label: sum(counter.values()) + len(vocabulary) for label, counter in counts.items()}
    weights = {token: math.log((counts['suspicious'][token] + 1) / totals['suspicious']) -
               math.log((counts['benign'][token] + 1) / totals['benign']) for token in vocabulary}
    return {'version': 'agentguard-text-nb-v1', 'algorithm': 'multinomial naive Bayes',
            'bias': math.log(documents['suspicious'] / documents['benign']), 'weights': weights,
            'training_examples': len(rows), 'threshold': 3.0}


@lru_cache(maxsize=1)
def load_model():
    return json.loads((DATA / 'model.json').read_text())


@lru_cache(maxsize=1)
def training_status():
    try:
        summary = DATA / 'training-status.json'
        if summary.is_file():
            return json.loads(summary.read_text())
        activation = load_model().get('activation', '')
        report = json.loads((DATA / ('evaluation-initial.json' if activation == 'user-selected-experimental' else 'evaluation.json')).read_text())
        return {'candidate': report['model'], 'training_examples': report['split_audit']['counts']['train'],
                'test': {k: v for k, v in report['benchmarks']['test'].items() if k != 'errors'},
                'email_regression': {k: v for k, v in report['benchmarks']['regression'].items() if k != 'errors'},
                'target_met': report['target']['passed'], 'experimental_active': activation == 'user-selected-experimental'}
    except (OSError, KeyError, ValueError, TypeError):
        return None


def predict(text, model=None):
    model = model or load_model()
    if model['version'] == 'agentguard-text-tfidf-v2':
        from .text_model import document_score
        value = document_score(text, model)
        return 'uncertain' if value is None else 'suspicious' if value >= model['threshold'] else 'benign'
    words = text.split()
    scores = []
    for start in range(0, len(words), 80):
        tokens = set(features(' '.join(words[start:start + 120])))
        known = tokens & model['weights'].keys()
        if len(known) >= 3:
            scores.append(model['bias'] + sum(model['weights'][token] for token in known))
    if not scores:
        return 'uncertain'
    return 'suspicious' if max(scores) >= model['threshold'] else 'benign'


def review_text(email, content):
    """Score separately so a long benign attachment cannot drown out another source."""
    sources = [('Email', email['subject'] + '\n' + email['body'])]
    skipped = []
    pdf_count = 0
    for part in content[1:]:
        if part['type'] == 'input_text':
            value = json.loads(part['text'])
            if 'text' in value:
                sources.append((value.get('untrusted_attachment', 'Attachment'), value['text']))
        elif part['type'] == 'input_file':
            name = part.get('filename', 'PDF')
            if pdf_count >= 2:
                skipped.append({'source': name, 'reason': 'Local PDF extraction budget reached.'})
                continue
            pdf_count += 1
            try:
                from .pdf_ingest import extract_pdf
                raw = base64.b64decode(part['file_data'].split(',', 1)[1], validate=True)
                extracted = extract_pdf(raw)
                sources.append((name + ' (extracted text only)', extracted['text']))
                skipped.append({'source': name, 'reason': 'PDF images and visual layout require the main AI review.'})
            except (ValueError, KeyError, IndexError, OSError):
                skipped.append({'source': name, 'reason': 'Local PDF text extraction unavailable; main AI review required.'})
        elif part['type'] == 'input_image':
            skipped.append({'source': 'Image', 'reason': 'Images require the main AI review.'})
    skipped.extend({'source': issue['source'], 'reason': issue['reason']} for issue in email.get('inspection_issues', []))
    try:
        model = load_model()
        results = [{'source': source, 'label': predict(text, model)} for source, text in sources]
    except (OSError, ValueError, KeyError, TypeError):
        return {'label': 'unavailable', 'scope': 'Text only · experimental', 'sources': []}
    labels = {result['label'] for result in results}
    label = 'suspicious' if 'suspicious' in labels else 'uncertain' if 'uncertain' in labels or skipped else 'benign'
    return {'label': label, 'model': model['version'], 'sources': results,
            'scope': 'Experimental text classifier; visual content uses the main AI review',
            'training_examples': model['training_examples'], 'benchmark': model.get('benchmark'),
            'target_met': model.get('target_met', False), 'unreviewed': skipped,
            'training_status': training_status(),
            'advisory_only': True}
