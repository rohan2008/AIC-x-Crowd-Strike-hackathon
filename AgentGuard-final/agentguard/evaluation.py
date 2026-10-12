"""Run identical inputs through isolated vulnerable/protected sandboxes."""
import argparse
from datetime import datetime, timezone
import json
import os
from time import perf_counter
from .supervisor import CONFIGURATIONS, execute_workflow
from .attacks import CASES
from .data import TICKET
from .defense import detect
from .sandbox import Sandbox
from .model import validate_images


def run(body, mode, configuration, reviewer_fault=False, images=None):
    settings = CONFIGURATIONS[configuration]
    sandbox = Sandbox(TICKET, settings["gateway"])
    started = perf_counter()
    error = None
    handoffs = []
    workflow = {"message": "Run did not finish.", "draft": None, "review": None,
                "supervisor_decision": None, "reviewer_stopped": False}
    try:
        workflow = execute_workflow(body, sandbox, mode, configuration, handoffs, reviewer_fault, images)
    except (ValueError, RuntimeError) as exc:
        error = str(exc)
    return {"protected": settings["gateway"], "configuration": configuration, "label": settings["label"],
            "mode": mode, "error": error, "handoffs": handoffs, **workflow,
            "elapsed_ms": round((perf_counter() - started) * 1000), **sandbox.summary()}


def compare(body, mode="simulation", reviewer_fault=False, images=None):
    if mode not in ("simulation", "live"):
        raise ValueError("Unsupported agent mode.")
    if not isinstance(reviewer_fault, bool) or (reviewer_fault and mode != "simulation"):
        raise ValueError("Reviewer fault injection is available only in simulation.")
    images = validate_images(images) if mode == "live" else []
    return {"mode": mode, "model": os.getenv("OPENAI_MODEL") if mode == "live" else None,
            "timestamp": datetime.now(timezone.utc).isoformat(), "ticket": TICKET,
            "body": body, "signals": detect(body), "reviewer_fault": reviewer_fault,
            **{name: run(body, mode, name, reviewer_fault, images) for name in CONFIGURATIONS}}


def validate_custom_cases(cases):
    if cases is None:
        return []
    if not isinstance(cases, list) or len(cases) > 10:
        raise ValueError("Custom test list must contain at most 10 cases.")
    required = {"id", "name", "kind", "category", "description", "body"}
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) not in (required, required | {"images"}):
            raise ValueError("Invalid custom test fields.")
        case["images"] = validate_images(case.get("images"))
        if not isinstance(case["id"], str) or not case["id"].startswith("custom-") or len(case["id"]) > 80 or case["id"] in seen:
            raise ValueError("Invalid or duplicate custom test ID.")
        seen.add(case["id"])
        for key, limit in (("name", 100), ("category", 100), ("description", 500), ("body", 12000)):
            if not isinstance(case[key], str) or not case[key].strip() or len(case[key]) > limit:
                raise ValueError(f"Invalid custom test {key}.")
        if case["kind"] not in ("attack", "benign"):
            raise ValueError("Custom test kind must be attack or benign.")
    return cases


def evaluate(mode="simulation", custom_cases=None):
    cases = CASES + validate_custom_cases(custom_cases)
    rows = [{"case": {key: value for key, value in case.items() if key != "images"}, **compare(case["body"], mode, images=case.get("images"))} for case in cases]
    metrics = {}
    for side in CONFIGURATIONS:
        # Failed runs are explicitly excluded, never counted as successful defenses.
        attacks = [r for r in rows if r["case"]["kind"] == "attack" and not r[side]["error"]]
        benign = [r for r in rows if r["case"]["kind"] == "benign" and not r[side]["error"]]
        metrics[side] = {"attack_successes": sum(r[side]["violation"] for r in attacks), "attack_count": len(attacks),
                         "benign_successes": sum(r[side]["task_completed"] for r in benign), "benign_count": len(benign),
                         "benign_blocked": sum(r[side]["blocked_calls"] > 0 for r in benign),
                         "reviewer_stops": sum(r[side]["reviewer_stopped"] for r in rows if not r[side]["error"]),
                         "errors": sum(bool(r[side]["error"]) for r in rows)}
    return {"mode": mode, "model": os.getenv("OPENAI_MODEL") if mode == "live" else None,
            "timestamp": datetime.now(timezone.utc).isoformat(), "metrics": metrics, "rows": rows,
            "limitation": "Curated local fixtures; simulation results are not evidence of an LLM vulnerability. "
                          "Task completion checks recipient, plan, and ISO renewal date; it is not a semantic grader."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["simulation", "live"], default="simulation")
    parser.add_argument("--output")
    args = parser.parse_args()
    report = evaluate(args.mode)
    if args.output:
        with open(args.output, "w") as handle:
            json.dump(report, handle, indent=2)
    print(json.dumps({"mode": report["mode"], "metrics": report["metrics"], "limitation": report["limitation"]}, indent=2))
    if any(metric["errors"] for metric in report["metrics"].values()):
        raise SystemExit(1)
