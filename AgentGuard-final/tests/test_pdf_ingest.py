import io
import subprocess
import unittest
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject

from agentguard.pdf_ingest import MAX_PDF_BYTES, extract_pdf, read_pdf
from agentguard.evaluation import compare
from server import Handler


def pdf_bytes(text="What is my plan?", pages=1, encrypted=False):
    writer = PdfWriter()
    for _ in range(pages):
        page = writer.add_blank_page(width=612, height=792)
        font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                                 NameObject('/Subtype'): NameObject('/Type1'),
                                 NameObject('/BaseFont'): NameObject('/Helvetica')})
        page[NameObject('/Resources')] = DictionaryObject({
            NameObject('/Font'): DictionaryObject({NameObject('/F1'): font})})
        stream = DecodedStreamObject()
        escaped = text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        stream.set_data(f'BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET'.encode())
        page[NameObject('/Contents')] = writer._add_object(stream)
    if encrypted:
        writer.encrypt('password')
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


class PdfTests(unittest.TestCase):
    def test_import_enters_existing_comparison_flow(self):
        result = extract_pdf(pdf_bytes())
        self.assertEqual(result['text'], 'What is my plan?')
        self.assertEqual(result['pages'], 1)
        self.assertTrue(compare(result['text'])['protected']['task_completed'])

    def test_pages_keep_reading_order(self):
        self.assertEqual(read_pdf(pdf_bytes(pages=2))['text'], 'What is my plan?\n\nWhat is my plan?')

    def test_invalid_and_oversized_uploads(self):
        for data in (b'', b'not a PDF', b'%PDF-' + b'x' * MAX_PDF_BYTES):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                extract_pdf(data)

    def test_unreadable_documents_have_actionable_errors(self):
        for data, expected in ((pdf_bytes(text=''), 'OCR'),
                               (pdf_bytes(encrypted=True), 'Password-protected'),
                               (pdf_bytes(pages=51), '50 pages'),
                               (pdf_bytes(text='x' * 12001), '12,000'),
                               (b'%PDF-invalid', 'Could not read')):
            with self.subTest(expected=expected):
                self.assertIn(expected, read_pdf(data)['error'])

    def test_timeout_is_reported(self):
        with patch('agentguard.pdf_ingest.subprocess.run', side_effect=subprocess.TimeoutExpired('pdf', 15)):
            with self.assertRaisesRegex(ValueError, 'timed out'):
                extract_pdf(b'%PDF-1.7')

    def test_http_import_and_origin_checks(self):
        data = pdf_bytes()
        def request(headers):
            handler = Handler.__new__(Handler)
            handler.server = type('Server', (), {'server_port': 8765})()
            handler.path = '/api/ingest/pdf'
            handler.headers = {'Host': 'localhost:8765', 'Content-Type': 'application/pdf',
                               'Content-Length': str(len(data)), **headers}
            handler.rfile = io.BytesIO(data)
            responses = []
            handler.respond = lambda status, payload: responses.append((status, payload))
            handler.do_POST()
            return responses[0]
        status, payload = request({})
        self.assertEqual(status, 200)
        self.assertEqual(payload['text'], 'What is my plan?')
        self.assertEqual(request({'Origin': 'https://outside.test'})[0], 403)
        self.assertEqual(request({'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(request({'Content-Length': str(MAX_PDF_BYTES + 1)})[0], 400)


if __name__ == '__main__':
    unittest.main()
