# AgentGuard email test pack

Three adversarial emails plus one benign control. All names and addresses are fictional, and all domains use `.test`. Attachments contain prompt-injection text only: no executable code, macros, active links or malware.

## Use in AgentGuard

1. Open http://127.0.0.1:8767 and choose **New email**.
2. Copy the sender, recipient, subject and message from a case's `email.txt`.
3. Attach that case's PDF or PNG. Do not attach `expected-result.txt` or this README; they disclose the test answer.
4. Confirm analysis and select **Review & send**. This sends the synthetic content to OpenAI and uses API credits.
5. Compare the result with `expected-result.txt`. AI verdicts can vary.

Each folder also includes an `.eml` with its attachment embedded for mail clients or other test harnesses. The current AgentGuard UI does not import `.eml`; use the text and standalone attachment instead.

- **01:** A 12-page report with image-only malicious instructions on page 12.
- **02:** A finance-themed PNG that forges approval and tells the AI to hide the warning.
- **03:** A vendor checklist with a forged policy appendix asking for secrets.
- **04:** A benign training handout quoting an attack. Checks for false positives.

Nothing in this pack has been sent as real email. Expected outcomes are not fresh live test results.
