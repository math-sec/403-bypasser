# 403-Bypasser

A versatile, concurrent scanner for discovering bypasses on forbidden web endpoints (`403 Forbidden`).

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)

---

### Overview

Ever stumbled upon a juicy endpoint like `/admin`, `/api/private`, or `/backups`, only to be met by a frustrating `403 Forbidden`? Often, this security is just a facade. Misconfigurations in reverse proxies, WAFs (Web Application Firewalls), or the web server itself can allow specially crafted requests to bypass these restrictions.

**403-Bypasser** automates the discovery of these misconfigurations, systematically and intelligently testing a wide range of known bypass techniques.

### ✨ Key Features

- **Intelligent Analysis:** Compares not only the **status code** but also the **response size** to detect subtle anomalies that other tools miss.
- **True Concurrency:** Process massive URL lists in a fraction of the time with fine-grained worker control (`-c`), ideal for large-scale scans.
- **Exhaustive Path Manipulation:** Executes a comprehensive battery of path manipulation tests, including:
    - Prefix and suffix payload injection on *every* segment of the URL path.
    - Advanced case permutations (`ADMIN`, `Admin`, `aDmIn`, etc.).
    - Creative character-by-character URL encoding, including single and double encoding.
- **Comprehensive Fuzzing:** Fuzzes HTTP methods, User-Agents, and Headers using customizable wordlists.
- **Advanced Techniques:** Includes tests for **Hop-by-Hop** header vulnerabilities.
- **Protocol Versions:** Automatically tests the target over modern HTTP/1.1 and HTTP/2 by default, while also explicitly probing for weaknesses using legacy protocols like HTTP/1.0 and HTTP/0.9.
- **Clear & Actionable Output:**
    - The output is color-coded for easy identification of bypasses and anomalies.
    - For every finding, the tool reports the **exact reason** (status change, size change, or both).
    - It generates a reproducible `curl` command for every finding, allowing for immediate validation and exploitation.
- **Highly Configurable:** Full control over timeouts, concurrency, and verbosity levels for debugging (`-v`).

### Techniques Implemented

This scanner uses a layered approach to maximize test coverage:

1.  **Exhaustive Path Manipulation**
    -   **Per-Segment Fuzzing:** Injects payloads (`..;`, `.json`, `%00`, etc.) as both prefixes and suffixes on *every* part of the path (`/api/v1` -> `/api.json/v1`, `/api/v1.json`).
    -   **Case Permutation:** Tests uppercase, lowercase, and mixed-case variations on each segment (`/admin` -> `/ADMIN`, `/Admin`, `/aDmIn`).
    -   **Character-by-Character URL Encoding:** Tests single and double URL encoding on each alphanumeric character (`/admin` -> `/%61dmin`, `/%2561dmin`).
    -   **Character Insertion:** Adds characters like `+` into the middle of path segments (`/admin` -> `/adm+in`).
    -   **Global Manipulation:** Adds wrappers (`//path//`) and suffixes (`/?`, `/*`, `/..`) to the full path.

2.  **Header Manipulation**
    -   **Header Injection:** Tests common bypass headers (`X-Forwarded-For`, `X-Rewrite-URL`, etc.) from a wordlist.
    -   **Hop-by-Hop Testing:** Attempts to smuggle headers through misconfigured proxies.

3.  **Protocol Fuzzing**
    -   **HTTP Methods:** Fuzzes alternative methods (`POST`, `PUT`, `PATCH`, etc.) on GET endpoints.
    -   **Protocol Versions:** Automatically tests the target over modern `HTTP/1.1` and `HTTP/2`, while also explicitly probing for weaknesses using legacy protocols like `HTTP/1.0` and `HTTP/0.9`.
    -   **User-Agents:** Fuzzes different User-Agent strings to circumvent client-based blocking.

🛠️ Installation
Using go install (Recommended)

```
git clone https://github.com/math-sec/403-bypasser.git
cd 403-bypasser
go build -o 403-bypasser .
./403-bypasser -h
```
