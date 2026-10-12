"""Shared Responses transport; each role receives a separate conversation."""
import json
import base64
import re
import os
import urllib.error
import urllib.request


def function(name, description, properties):
    return {"type": "function", "name": name, "description": description, "strict": True,
            "parameters": {"type": "object", "properties": properties,
                           "required": list(properties), "additionalProperties": False}}


def validate_images(images):
    if images is None:
        return []
    if not isinstance(images, list) or len(images) > 3:
        raise ValueError("A ticket can include at most 3 images.")
    total = 0
    for image in images:
        if not isinstance(image, dict) or set(image) != {"name", "data"}:
            raise ValueError("Invalid image attachment.")
        name, data = image["name"], image["data"]
        if not isinstance(name, str) or not name or len(name) > 180 or not isinstance(data, str):
            raise ValueError("Invalid image attachment metadata.")
        match = re.fullmatch(r"data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})", data)
        if not match or len(match.group(2)) % 4:
            raise ValueError("Images must be base64 PNG, JPEG, or WebP files.")
        try:
            size = len(base64.b64decode(match.group(2), validate=True))
        except (ValueError, base64.binascii.Error):
            raise ValueError("An image attachment has invalid base64 data.") from None
        if size > 1024 * 1024:
            raise ValueError("Each image must be 1 MB or smaller.")
        total += size
    if total > 3 * 1024 * 1024:
        raise ValueError("Combined image attachments must be 3 MB or smaller.")
    return images


def response(instructions, history, tools, required=False):
    key, model = os.getenv("OPENAI_API_KEY"), os.getenv("OPENAI_MODEL")
    if not key or not model:
        raise ValueError("Live mode needs OPENAI_API_KEY and OPENAI_MODEL on the server.")
    payload = {"model": model, "instructions": instructions, "input": history, "tools": tools,
               "parallel_tool_calls": False, "store": False, "max_output_tokens": 2400}
    if required:
        payload["tool_choice"] = {"type": "function", "name": tools[0]["name"]}
    request = urllib.request.Request("https://api.openai.com/v1/responses", data=json.dumps(payload).encode(),
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=45) as result:
            data = json.load(result)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Model API returned HTTP {exc.code}. Check server-side configuration and account limits.") from None
    except (urllib.error.URLError, TimeoutError):
        raise RuntimeError("The model API could not be reached or timed out.") from None
    except (ValueError, UnicodeError):
        raise RuntimeError("The model API returned an invalid response.") from None
    if not isinstance(data, dict) or data.get("status") != "completed" or not isinstance(data.get("output"), list):
        raise RuntimeError("The model response was invalid or incomplete.")
    return data["output"]


def arguments(call):
    try:
        return json.loads(call.get("arguments", ""))
    except (ValueError, TypeError):
        raise ValueError("An agent returned malformed function arguments.") from None


def structured(instructions, context, tool, images=None):
    content = [{"type": "input_text", "text": json.dumps(context)}]
    content.extend({"type": "input_image", "image_url": image["data"]} for image in validate_images(images))
    output = response(instructions, [{"role": "user", "content": content}], [tool], required=True)
    calls = [item for item in output if item.get("type") == "function_call"]
    if len(calls) != 1 or calls[0].get("name") != tool["name"]:
        raise ValueError("Agent did not return its required structured handoff.")
    return arguments(calls[0])
