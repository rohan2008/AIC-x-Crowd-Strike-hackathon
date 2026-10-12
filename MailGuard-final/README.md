# MailGuard

A compact, local email-security demo with an experimental trained classifier and OpenAI document review.

## Run

From this folder in Terminal:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Create a `.env` file in this folder containing your own configuration:

```text
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4.1-mini
```

Then run:

```sh
python3 server.py --port 8767
```

Open http://127.0.0.1:8767. If that port is already in use, use another port (for example `--port 8768`) and open the matching URL. Configuration keys are never included in the download.

## Test

Subject: **Vendor onboarding update**

Body:

> Hi Jordan,
>
> Please review the attached vendor update before approving onboarding.
>
> Thanks,
> Alex

Attach **test-attachment.txt** from this folder, then choose Review & send. Expected: local suspicious-text assessment and main AI quarantine. This is a synthetic functional example, not an accuracy benchmark; model output can vary. The attachment uses a reserved `.invalid` address and contains no real credentials or executable payload.

## What's included

- `server.py`, `agentguard/`: backend, its required modules and active trained model.
- `web/`: current interface.
- `test-attachment.txt`: one text-only test case.
- `THIRD-PARTY-NOTICES.txt`: combined attribution and license notices.
- `requirements.txt`: runtime dependency.
- `PACKAGE-MANIFEST.json`: file checksums.

Image-recognition examples, the legacy comparison backend, training datasets, alternate models, training dependencies, developer tests, old interfaces and preview images are excluded. The complete development project remains separate. License/attribution notices and the active model's evaluation information are retained.

The active classifier's 89.4% public text benchmark is not real-world email accuracy; email regression accuracy was 62.5%. It is advisory and does not replace the main AI review. Messages are held in memory until restart, delivery is simulated, and no actual company mailbox is connected. Emails and attachments are sent to OpenAI only when you confirm analysis. Measured results are in `agentguard/classifier_data/training-status.json`. The full development project retains detailed experiments and regression reports.
