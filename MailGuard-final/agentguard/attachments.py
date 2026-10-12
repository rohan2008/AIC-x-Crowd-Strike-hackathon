"""Bounded, non-executing inspection of arbitrary attachment bytes."""
import base64
import io
import json
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import PurePosixPath
from xml.etree import ElementTree

MAX_FILES = 25
MAX_BYTES = 20 * 1024 * 1024
MAX_EXPANDED = 30 * 1024 * 1024
MAX_TEXT = 120000


class AttachmentReader:
    def __init__(self):
        self.content = []
        self.issues = []
        self.count = self.bytes = self.characters = 0

    def hold(self, name, reason):
        self.issues.append({'source': name, 'evidence': 'Content could not be fully inspected.', 'reason': reason})

    def text(self, name, text):
        remaining = max(0, MAX_TEXT - self.characters)
        if len(text) > remaining:
            self.hold(name, 'Text exceeds the review limit; the unreviewed remainder requires manual inspection.')
        text = text[:remaining]
        self.characters += len(text)
        self.content.append({'type': 'input_text', 'text': json.dumps({'untrusted_attachment': name, 'text': text})})

    def read(self, name, raw, depth=0):
        self.count += 1
        self.bytes += len(raw)
        if self.count > 150 or self.bytes > MAX_EXPANDED or depth > 5:
            self.hold(name, 'Attachment expansion or nesting limit reached.'); return
        suffix = PurePosixPath(name.lower()).suffix
        if raw.startswith(b'%PDF-'):
            self.content.append({'type': 'input_file', 'filename': name if suffix == '.pdf' else name + '.pdf',
                                 'file_data': 'data:application/pdf;base64,' + base64.b64encode(raw).decode()})
            return
        image_type = ('png' if raw.startswith(b'\x89PNG\r\n\x1a\n') else 'jpeg' if raw.startswith(b'\xff\xd8\xff')
                      else 'webp' if raw.startswith(b'RIFF') and raw[8:12] == b'WEBP' else None)
        if image_type:
            self.text(name, 'The following image belongs to this attachment.')
            self.content.append({'type': 'input_image', 'image_url': f'data:image/{image_type};base64,' + base64.b64encode(raw).decode(), 'detail': 'high'})
            return
        if suffix in ('.eml', '.mime'):
            self.email(name, raw, depth); return
        if raw.startswith(b'PK'):
            self.archive(name, raw, depth, suffix in ('.docx', '.pptx', '.xlsx', '.odt', '.ods', '.odp')); return
        if suffix in ('.pdf', '.png', '.jpg', '.jpeg', '.webp', '.exe', '.dll', '.dmg', '.bin', '.so', '.msi', '.doc', '.xls', '.ppt', '.msg', '.mp3', '.mp4', '.mov', '.gif', '.heic', '.tiff', '.rar', '.7z', '.gz'):
            self.hold(name, 'This binary, legacy, media or malformed format requires manual inspection.'); return
        try:
            text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
            if any(ord(char) < 32 and char not in '\t\r\n' for char in text):
                raise ValueError('binary content')
            self.text(name, text or '[Empty file]')
        except (UnicodeError, ValueError):
            self.hold(name, 'The file is not readable text or a supported document/image format. Manual inspection is required.')

    def email(self, name, raw, depth):
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw)
            self.text(name, '\n'.join(f'{key}: {value}' for key, value in message.items()))
            self.mime_part(name, message, depth + 1)
        except (ValueError, LookupError, UnicodeError, RecursionError):
            self.hold(name, 'The email or an embedded part could not be decoded.')

    def mime_part(self, name, part, depth):
        if depth > 12:
            self.hold(name, 'Email nesting limit reached.'); return
        if part.defects:
            self.hold(name, 'Malformed email structure requires manual inspection.')
        if part.is_multipart():
            for index, child in enumerate(part.iter_parts()):
                self.count += 1
                if self.count > 150:
                    self.hold(name, 'Too many embedded email parts.'); return
                self.mime_part(f'{name}/part-{index + 1}', child, depth + 1)
            return
        raw = part.get_payload(decode=True)
        if part.defects:
            self.hold(name, 'Email content has decoding defects and requires manual inspection.')
        if raw is None:
            self.hold(name, 'An email part could not be decoded.'); return
        filename = part.get_filename()
        if filename:
            self.read(f'{name}/{filename}', raw, depth); return
        if part.get_content_maintype() == 'text':
            try:
                self.text(name, raw.decode(part.get_content_charset() or 'utf-8'))
            except (UnicodeError, LookupError):
                self.hold(name, 'Email text encoding could not be decoded.')
        else:
            self.read(name, raw, depth)

    def archive(self, name, raw, depth, office=False):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = archive.infolist()
                if len(entries) > 500 or sum(item.file_size for item in entries) > MAX_EXPANDED - self.bytes:
                    self.hold(name, 'Archive expands beyond the inspection limit.'); return
                for entry in entries:
                    if entry.is_dir(): continue
                    child = name + '/' + entry.filename
                    if entry.flag_bits & 1:
                        self.hold(child, 'Encrypted archive entry cannot be inspected.'); continue
                    with archive.open(entry) as stream:
                        data = stream.read(MAX_EXPANDED - self.bytes + 1)
                    if office and entry.filename.endswith(('.xml', '.rels')):
                        self.count += 1; self.bytes += len(data)
                        if self.count > 150 or self.bytes > MAX_EXPANDED:
                            self.hold(child, 'Document inspection limit reached.'); return
                        try:
                            if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper(): raise ValueError()
                            xml = ElementTree.fromstring(data)
                            text = '\n'.join(value for node in xml.iter() for value in ([node.text or ''] + list(node.attrib.values())) if value.strip())
                            self.text(child, text)
                        except (ElementTree.ParseError, ValueError):
                            self.hold(child, 'Document XML could not be safely inspected.')
                    else:
                        self.read(child, data, depth + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, ValueError):
            self.hold(name, 'Archive or document could not be fully inspected.')
