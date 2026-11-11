# System Architecture Diagram

This diagram shows Secure Vibe Delivery's internal components, the direction data flows
between them, and how it reaches its most important external dependency: **Snyk cloud**.

## How it connects to Snyk cloud

The server never calls Snyk's API itself. The Security Check starts the **Snyk CLI as a local
subprocess**, and the CLI talks to Snyk cloud over HTTPS with the token from a browser sign-in
done once in guided setup. Whether a scan runs therefore depends on the tool resolver finding the
CLI on that machine: on PATH, in the server's own cache, or (for Semgrep and Locust) through `uvx`.

## Diagram

```mermaid
flowchart TD
    User(["Developer / reviewer"])

    subgraph Assistant["People & assistant"]
        AST["AI Assistant<br/>Claude Code · Copilot Chat"]
    end

    subgraph Server["MCP server (uvx child process, stdio)"]
        MCP["MCP Server<br/>FastMCP · 9 svd_* tools"]
        SK["Skills<br/>5 skill:// fixing guides"]
        SETUP["Guided Setup<br/>svd_setup"]
        DOC["Doctor<br/>svd_doctor"]
        PIPE["Run Pipeline<br/>background job · run_id"]
        LGEN["Locustfile Generator<br/>OpenAPI → routes"]
        subgraph Checks
            SEC["Security Check<br/>Snyk · Semgrep · provenance"]
            FUN["Functional Check<br/>70% coverage gate"]
            PERF["Performance Check<br/>1.5× expected peak"]
        end
        GATE["Go-Live Gate<br/>GO · PROVISIONAL · NO-GO"]
        REND["Report Renderer<br/>Jinja2 · health score"]
    end

    subgraph Tools["Local tools (subprocesses)"]
        SCAN["Snyk CLI · Semgrep<br/>security scanners"]
        PYT["pytest / Jest<br/>project test runner"]
        LOC["Locust<br/>load generator · uvx"]
    end
    RUNS[("Run Records<br/>.svd/runs · .svd/reports")]
    CHROME["Chrome / Edge<br/>headless PDF (optional)"]

    SNYK[["Snyk cloud<br/>vuln DB · Code · sign-in"]]
    SGR[["Semgrep registry<br/>rules · optional sign-in"]]
    REG[["PyPI · npm<br/>package age · uvx downloads"]]
    TEST[["Test environment<br/>never production"]]

    User -->|chat| AST
    AST -->|"MCP · stdio"| MCP
    AST -.->|"polls svd_status"| MCP
    MCP -->|serves| SK
    MCP --> SETUP
    MCP --> DOC
    MCP -->|"svd_run"| PIPE
    MCP --> LGEN
    PIPE -->|"runs in order"| SEC
    PIPE --> FUN
    PIPE --> PERF
    SEC -->|subprocess| SCAN
    FUN -->|"runs tests"| PYT
    PERF -->|"load profile"| LOC
    SETUP -->|"auth, login"| SCAN
    DOC -->|"versions, whoami"| SCAN
    SEC -->|"HTTPS"| REG
    SCAN -->|"HTTPS, token"| SNYK
    SCAN -->|HTTPS| SGR
    SCAN -->|"uvx fetch"| REG
    LOC -->|"uvx fetch"| REG
    LOC -->|"load test"| TEST
    SETUP -->|"CLI download"| SNYK
    PIPE -->|results| GATE
    PIPE -->|"run state"| REND
    REND -->|"print PDF"| CHROME
    REND -->|"HTML, summary.json"| RUNS
    PIPE -->|"raw output"| RUNS
    PIPE -.->|"opens report"| User

    classDef external fill:#333,stroke:#999,color:#fff;
    class SNYK,SGR,REG,TEST external;
```

**Reading the diagram:**

- Solid arrows = request/command direction; dashed = polling or a reverse-direction hand-back (the assistant polling a run, the report opening for the developer).
- Dark boxes = external systems Secure Vibe Delivery depends on but doesn't control.
- Everything inside "MCP server" runs in one local process; the local tools run as subprocesses of it.
