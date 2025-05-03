# HTTP Request Smuggling Detection Tool – Product Requirements Document

## 1. Purpose
Provide an open-source Python toolkit that automatically detects, confirms, and reports HTTP request-smuggling vulnerabilities (CL.TE, TE.CL, H2.TE, H2.CL, CL.0, H2.0) inside laboratory or production-like environments.

## 2. Problem Statement
HTTP request smuggling occurs when a front-end and back-end server interpret the boundaries of an HTTP request differently. The attack enables cache poisoning, credential hijacking, and even full request forgery. Current scanners either miss modern H2-to-H1 variants or cannot send the malformed, non-RFC-compliant payloads required for reliable detection.

## 3. Goals & Objectives
* Build custom HTTP/1.1 and HTTP/2 clients that allow **full raw control** over headers, framing, and body data so that malformed requests can be transmitted exactly as crafted.
* Implement automated probes derived from PortSwigger research to detect six major smuggling classes:
  1. **CL.TE**  – Conflicting `Content-Length` & `Transfer-Encoding` (front-end CL, back-end TE)
  2. **TE.CL**  – Opposite interpretation (front-end TE, back-end CL)
  3. **H2.TE**  – HTTP/2 front-end vs HTTP/1 back-end using TE smuggling
  4. **H2.CL**  – HTTP/2 front-end vs HTTP/1 back-end using CL smuggling
  5. **CL.0**   – `Content-Length: 0` desync variant
  6. **H2.0**   – HTTP/2 `content-length: 0` variant
* Deliver a CLI utility (`hrs_finder`) that runs selected or full test-suites against a target and outputs JSON/CSV & colourised console summaries.
* Design the codebase for easy extensibility so that new smuggling primitives or protocols (e.g. HTTP/3) can be added with minimal change.

## 4. Out of Scope
* Automatic mitigation (handled by a separate future module).
* Active exploitation beyond proof-of-concept echo injections.

## 5. Personas & Use-Cases
| Persona | Need |
|---------|------|
| Security Researcher | Validate whether a lab setup is vulnerable and reproduce academic techniques. |
| DevSecOps Engineer | Scan staging/production before new load-balancer rules or proxies go live. |
| Student | Learn request smuggling internals by reading clean, well-commented reference code. |

## 6. Functional Requirements
FR-1  Custom **HTTP/1.1 Client**
  * Raw TCP & TLS sockets (asyncio-stream).
  * Manual construction of request lines, headers (maintain duplicates/order/casing/whitespace), and bodies.
  * Optional keep-alive & pipelining to support differential timing attacks.

FR-2  Custom **HTTP/2 Client**
  * Built atop `h2` for framing control; bypass default sanity checks where necessary.
  * Ability to send:
    * HEADERS frames containing duplicate pseudo-headers or conflicting `content-length` values.
    * DATA frames with partial bodies, withheld termination, or extra padding.

FR-3  **Probe Engine**
  * Encapsulates each smuggling technique (payload, expected responses, validation logic).
  * Supports cut-down *lite* mode (non-destructive) vs *full* mode (complete desync payloads).

FR-4  **Detection Logic**
  * Methods: reflection, differential response sizing, timing anomalies, connection state analysis.
  * Each probe returns a score → classifier marks **vulnerable / uncertain / safe**.

FR-5  **CLI Interface**
  * `hrs_finder scan https://host[:port] [--techniques CL.TE,TE.CL] [--h2] [--output result.json]`.
  * Interactive progress bar, rich table results.

FR-6  **Reporting**
  * Colourised console, JSON, CSV, and Markdown summary.
  * Exit-codes: `0`=no finding, `1`=vulnerable, `2`=uncertain/errors.

FR-7  **Logging & Verbosity**
  * `--debug` to dump raw requests/responses to file.

## 7. Non-Functional Requirements
* **Performance:** Complete default scan against single endpoint in < 90 seconds on 100 ms RTT link.
* **Reliability:** Do not crash on non-standard responses; graceful timeouts.
* **Extensibility:** Strict module boundaries, clean interface contracts.
* **Code Quality:** 100 % mypy-checked, `ruff` lint clean, ≥ 80 % unit test coverage.

## 8. Architecture & Module Breakdown
```
hrs_finder/
 ├─ __init__.py
 ├─ cli/            # click-based entrypoints
 │   └─ main.py
 ├─ clients/
 │   ├─ http1.py    # Low-level asyncio TCP client
 │   └─ http2.py    # Hyper-h2 wrapper
 ├─ probes/
 │   ├─ base.py
 │   ├─ cl_te.py
 │   ├─ te_cl.py
 │   ├─ h2_te.py
 │   ├─ h2_cl.py
 │   ├─ cl0.py
 │   └─ h20.py
 ├─ detectors/
 │   └─ analyse.py  # heuristics & scoring
 ├─ utils/
 │   ├─ tls.py
 │   └─ logging.py
 └─ tests/
```

## 9. Technology Stack
* **Python 3.11**
* `asyncio`, `ssl`, `hyper-h2`, `hpack`, `click`, `rich`, `colorama`, `pytest`, `mypy`, `ruff`.

## 10. Milestones & Timeline
| Milestone | Deliverables | Duration |
|-----------|--------------|----------|
| M1 | Project skeleton, async HTTP/1.1 client, CLI skeleton | Week 1 |
| M2 | CL.TE & TE.CL probes + detection | Week 2–3 |
| M3 | HTTP/2 client, H2.* probes | Week 4–5 |
| M4 | Reporting, docs, CI pipeline | Week 6 |

## 11. Risk & Mitigation
* **Complex TLS edge-cases** → rely on Python’s `ssl` w/ ALPN; include fallback.
* **Library safety checks blocking malformed frames** → fork/patch `hyper-h2` frame validators locally.
* **False-positives/negatives** → implement multi-probe confirmation & manual review hints.

## 12. Glossary
* **CL.TE** – Content-Length / Transfer-Encoding desync (front-end uses CL).
* **TE.CL** – Transfer-Encoding / Content-Length desync.
* **H2.TE / H2.CL** – HTTP/2 to HTTP/1 variants.
* **CL.0 / H2.0** – Variants relying on `Content-Length: 0`.

## 13. References
* PortSwigger Research – HTTP Request Smuggling Reborn (2019-2024)
  * https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
  * https://portswigger.net/research/http2
  * https://portswigger.net/research/browser-powered-desync-attacks#csd
* RFC 7230, RFC 7540, RFC 9113
