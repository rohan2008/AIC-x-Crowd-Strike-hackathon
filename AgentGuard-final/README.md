# AgentGuard · Company mail

A local company email firewall demo. Write an email, attach PDFs or images, and review the AI's decision before simulated delivery. There is no connection to a real company mailbox and no real email is sent.

## Run

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 server.py --port 8767
```

Open **http://127.0.0.1:8767**. Opening `web/index.html` directly only shows a preview; the app needs its Python server.

Configure `OPENAI_API_KEY` and `OPENAI_MODEL` in the server environment or the project’s local `.env` file. The environment takes precedence. `.env` is excluded from Git. Restart the server after configuration changes. The configured model must support Responses function calling, images and PDF file inputs. The current local setup uses `gpt-4.1-mini`.

## Email workflow

1. Write a sender, recipient, subject and message. The example buttons load synthetic test emails.
2. Drag any files or folders into the attachment area, or use the file/folder pickers. All extensions are accepted, including empty files. Limits: 25 top-level attachments, 10 MB per file and 20 MB total. Nested folder paths are preserved. An oversized batch adds nothing. Folder traversal is limited to 1,000 entries and 20 levels.
3. Confirm OpenAI analysis, then choose **Review & send**. The full email and original attachments are sent to OpenAI and use API credits.
4. The server applies the review: low risk is delivered to the demo inbox, medium risk includes a recipient warning, and high risk is quarantined. Incomplete coverage is also quarantined. API errors or invalid reviews never deliver the email.
5. Select a message to read its summary, recipient warning and source-specific AI findings. Quarantined bodies are available under security review, not in the recipient inbox.

Plain text (including TXT, Markdown, CSV, JSON, HTML and code) is read locally. EML/MIME messages include headers, body parts and embedded attachments. ZIP archives are inspected recursively in memory; DOCX, PPTX, XLSX and OpenDocument packages include XML text, relationships and embedded images. Files are never extracted to disk or executed. Inspection is bounded to 30 MB expanded content, 120,000 text characters and 150 inspected parts; reaching a limit forces manual review. Unknown binary formats, legacy Office documents, audio/video and encrypted or unreadable entries are accepted but force quarantine regardless of the AI verdict.

PDFs are supplied as original file inputs so the model can examine extracted text and page images, including scans and embedded images. Oversized or malformed upload requests are rejected. Invalid PDFs may fail the model request; nothing is delivered when review fails. Very large documents should be split into smaller files. No OCR or threat detection is guaranteed. The scanner does not execute attachments, follow links or have email-sending tools.

The company identity and addresses are fictional. The sender field is demo input, not authenticated identity. This prototype uses an AI risk assessment and code-enforced delivery policy; it cannot determine that someone is a spy or guarantee every hidden instruction will be found. It does not perform antivirus analysis, continuous external mailbox monitoring, production authentication or attachment sanitization.

## Storage and limits

The server retains up to 100 reviewed messages in memory until restart. It retains message text, attachment names and review results, but does not retain attachment bytes after analysis or save emails to disk. Recipients and administrators are simulated views in the same local app. The server binds to loopback and checks Host and Origin headers. Only one review or legacy comparison runs at a time.

## Validation

```sh
.venv/bin/python -m unittest discover -s tests -v
node --check web/app.js
```

The original support-agent comparison backend and its tests remain available. The earlier interface source is preserved in `web/legacy/`. The email scanner is in `agentguard/mail.py`; the HTTP endpoints are in `server.py`.
