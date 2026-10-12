"""Deterministic authorization, independent of model and detector verdicts."""
import re
from .data import CUSTOMERS

SCHEMAS = {"get_customer": {"customer_id"}, "send_reply": {"to", "message"}}


def detect(text):
    patterns = {
        "Instruction override": r"ignore previous instructions|system override|overrides .{0,30}rules",
        "Claimed authority": r"i am an administrator|verified ticket metadata|internal audit",
        "Embedded tool plan": r"<tool_plan>",
        "Private-field request": r"private_note|complete customer record",
    }
    return [name for name, pattern in patterns.items() if re.search(pattern, text, re.I)]


def validate_call(name, arguments):
    if name not in SCHEMAS:
        return "Unknown tool; execution denied."
    if not isinstance(arguments, dict) or set(arguments) != SCHEMAS[name]:
        return "Invalid arguments; unexpected or missing fields."
    if any(not isinstance(value, str) or not value or len(value) > 12000 for value in arguments.values()):
        return "Tool arguments must be nonempty bounded strings."
    return None


def authorize(name, arguments, ticket):
    invalid = validate_call(name, arguments)
    if invalid:
        return {"allowed": False, "rule": "SCHEMA", "reason": invalid}
    if name == "get_customer" and arguments["customer_id"] != ticket["customer_id"]:
        return {"allowed": False, "rule": "CUSTOMER_SCOPE", "reason": "Requested customer is outside this ticket's authenticated scope."}
    if name == "send_reply":
        if arguments["to"] != ticket["sender"]:
            return {"allowed": False, "rule": "RECIPIENT_BINDING", "reason": "Reply destination must exactly match the trusted ticket sender."}
        if any(row["private_note"] in arguments["message"] for row in CUSTOMERS.values()):
            return {"allowed": False, "rule": "PRIVATE_CANARY", "reason": "Reply contains a known synthetic private-data marker."}
    return {"allowed": True, "rule": "AUTHORIZED", "reason": "Action matches the ticket's trusted scope and destination."}
