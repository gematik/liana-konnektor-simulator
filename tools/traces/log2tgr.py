#!/usr/bin/env python3
#
# Copyright 2026 gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

"""Converts a popp-client log (Spring-WS MessageTracing at TRACE) into a Tiger trace (.tgr).

Only the SOAP pairs with the Konnektor are taken over:
    ... o.s.ws.client.MessageTracing.sent     : Sent request [<Envelope>]
    ... o.s.ws.client.MessageTracing.received : Received response [<Envelope>] for request [<Envelope>]
The log contains no HTTP headers; they are reconstructed:
- Path: first line "Service path for '<service>' is '<path>'" of the same thread since the last request.
  popp-client looks up twice per call (endpoint, then version); for ReadCardCertificate and
  ExternalAuthenticate the second lookup is CardService, the endpoint is the first.
- SOAPAction: namespace of the operation + "#" + operation (the way popp-client builds it)
- Response: 200, 500 for a SOAP fault; Content-Type text/xml (SOAP 1.1)
UUIDs depend only on the log line, so converting twice yields the same file.

Usage (from the repo root):
    python3 -I tools/traces/log2tgr.py <log> <target.tgr> [--konnektor host:port]
"""
import argparse
import base64
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
LINE = re.compile(r"^(?P<ts>\S+)\s+\w+\s+\d+\s+---\s+\[\s*(?P<thread>[^\]]+?)\]\s+(?P<logger>\S+)\s+:\s(?P<msg>.*)$")
SERVICE_PATH = re.compile(r"Service path for '(?P<service>\w+)' is '(?P<path>[^']+)'")
SENT = re.compile(r"^Sent request \[(?P<env>.*)\]$")
RECEIVED = re.compile(r"^Received response \[(?P<env>.*?)\] for request \[.*\]$")
CONNECTOR_URL = re.compile(r"from '(?P<url>https?://[^/']+)")
OPERATION = re.compile(r"<SOAP-ENV:Body><(?:(?P<prefix>\w+):)?(?P<op>\w+)(?P<attrs>[^>]*)>")
CLIENT = "popp-client:8081"


def operation(envelope: str) -> tuple[str, str]:
    """Name and namespace of the operation in the SOAP body."""
    m = OPERATION.search(envelope)
    if not m:
        raise ValueError(f"keine Operation im Body: {envelope[:120]}")
    attr = f'xmlns:{m["prefix"]}' if m["prefix"] else "xmlns"
    ns = re.search(rf'{attr}="([^"]+)"', m["attrs"])
    return m["op"], ns.group(1) if ns else ""


def iso(ts: str) -> str:
    return datetime.fromisoformat(ts).isoformat()


def message(log: Path, line_no: int, seq: int, sender: str, receiver: str, kind: str, ts: str, raw: bytes,
            paired: str | None = None) -> dict:
    entry = {
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{log.name}#{line_no}")),
        "sequenceNumber": seq,
        "senderHostname": sender,
        "receiverHostname": receiver,
        "messageKind": kind,
        "timestamp": iso(ts),
    }
    if paired:
        entry["pairedMessageUuid"] = paired
    entry["rawMessageContent"] = base64.b64encode(raw).decode("ascii")
    return entry


def http_request(path: str, host: str, envelope: str) -> bytes:
    op, ns = operation(envelope)
    body = envelope.encode("utf-8")
    head = (f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: text/xml; charset=utf-8\r\n"
            f'SOAPAction: "{ns}#{op}"\r\n'
            f"Content-Length: {len(body)}\r\n\r\n")
    return head.encode("ascii") + body


def http_response(envelope: str) -> bytes:
    body = envelope.encode("utf-8")
    status = "500 Internal Server Error" if "<SOAP-ENV:Fault>" in envelope else "200 OK"
    head = (f"HTTP/1.1 {status}\r\n"
            "Content-Type: text/xml; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n\r\n")
    return head.encode("ascii") + body


def convert(log: Path, konnektor: str | None) -> list[dict]:
    paths: dict[str, str] = {}
    pending: dict[str, tuple[int, str, str, str]] = {}
    entries: list[dict] = []
    for line_no, text in enumerate(log.read_text(encoding="utf-8").splitlines(), 1):
        m = LINE.match(ANSI.sub("", text))
        if not m:
            continue
        thread, msg = m["thread"], m["msg"]
        if konnektor is None and (url := CONNECTOR_URL.search(msg)):
            konnektor = re.sub(r"^https?://", "", url["url"])
            konnektor += "" if ":" in konnektor else (":443" if url["url"].startswith("https") else ":80")
        if sp := SERVICE_PATH.search(msg):
            paths.setdefault(thread, sp["path"])
        elif m["logger"].endswith("MessageTracing.sent") and (s := SENT.match(msg)):
            if thread not in paths:
                raise ValueError(f"Zeile {line_no}: kein Dienstpfad für Thread {thread}")
            pending[thread] = (line_no, m["ts"], s["env"], paths.pop(thread))
        elif m["logger"].endswith("MessageTracing.received") and (r := RECEIVED.match(msg)):
            if thread not in pending:
                raise ValueError(f"Zeile {line_no}: Antwort ohne Request im Thread {thread}")
            if konnektor is None:
                raise ValueError("Konnektor-Adresse nicht im Log, --konnektor angeben")
            req_line, req_ts, req_env, path = pending.pop(thread)
            request = message(log, req_line, len(entries), CLIENT, konnektor, "REQUEST", req_ts,
                              http_request(path, konnektor, req_env))
            entries.append(request)
            entries.append(message(log, line_no, len(entries), konnektor, CLIENT, "RESPONSE", m["ts"],
                                   http_response(r["env"]), paired=request["uuid"]))
    if pending:
        raise ValueError(f"Requests ohne Antwort: Zeilen {[v[0] for v in pending.values()]}")
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument("tgr", type=Path)
    parser.add_argument("--konnektor", help="host:port des Konnektors, sonst aus „Downloading connector.sds from …“")
    args = parser.parse_args()
    entries = convert(args.log, args.konnektor)
    args.tgr.parent.mkdir(parents=True, exist_ok=True)
    args.tgr.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries), encoding="utf-8")
    print(f"{len(entries) // 2} SOAP-Paare → {args.tgr}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
