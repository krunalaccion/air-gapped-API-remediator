---
name: coding-standards
description: >-
  Universal coding standards, style guidelines, design patterns, and architectural
  conventions for modern Python projects. Follow these standards when writing,
  reviewing, refactoring, or testing code.
---

# Universal Python Coding Standards

This document defines the coding standards, design conventions, and architectural
guidelines applicable across modern Python projects. Contributors and automated
agents should follow these standards to ensure consistency, maintainability,
and high code quality.

---

## 1. Python Runtime & Environment

### 1.1 Baseline Compatibility
- **Target Runtime**: Maintain compatibility with the project's baseline Python version (typically Python ≥ 3.9).
- **Postponed Evaluation of Annotations**: Always declare `from __future__ import annotations` as the first import in every Python source file to enable PEP 563 / PEP 604 type annotation syntax.
- **Language Features**: Do not use language features newer than the declared baseline (e.g., avoid `match`/`case` if supporting Python 3.9).

### 1.2 Dependency Principles
- **Standard Library First**: Prefer Python standard library modules (`pathlib`, `json`, `dataclasses`, `urllib`, `http.server`, `unittest`) over heavy third-party packages whenever possible.
- **Optional Dependencies**: Any non-essential external dependencies (e.g., `pyyaml`, `pydantic`, `requests`) must be treated as optional extras and imported inside defensive `try/except ImportError` blocks.

---

## 2. Code Formatting & Style

### 2.1 Layout & Formatting Rules

| Rule | Standard |
| :--- | :--- |
| **Indentation** | 4 spaces per indentation level. Never use tabs. |
| **Line Length** | Soft limit of 100–120 characters for code and docstrings. |
| **String Quotes** | Double quotes (`"..."`) preferred for general strings; single quotes (`'...'`) for dictionary keys or internal identifiers when preferred. |
| **Trailing Commas** | Include a trailing comma in multi-line lists, tuples, dictionaries, and parameter lists. |
| **Blank Lines** | Two blank lines between top-level classes/functions; one blank line between methods within a class. |
| **File Encodings** | Always specify `encoding="utf-8"` when reading or writing text files via `open()` or `Path.read_text()` / `Path.write_text()`. |
| **Path Handling** | Use `pathlib.Path` instead of legacy `os.path` functions. |

### 2.2 Entry Point Guards
Every executable script or runnable module must guard its execution with:

```python
if __name__ == "__main__":
    main()
```

---

## 3. Import Conventions

### 3.1 Import Ordering

Imports must follow a 4-tier structure separated by blank lines:

```python
# 1. __future__ imports
from __future__ import annotations

# 2. Standard library imports (alphabetical)
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# 3. Third-party packages (alphabetical, guarded if optional)
try:
    import yaml
except ImportError:
    yaml = None

# 4. Internal / application imports
from .config import AppConfig
from .services import BaseService
```

### 3.2 Resilient Package Imports

When modules are intended to be executed both as part of an installed package and as standalone CLI scripts, provide fallback import logic:

```python
try:
    from .config import AppConfig
    from .service import CoreService
except (ImportError, ValueError):
    from mypackage.config import AppConfig
    from mypackage.service import CoreService
```

### 3.3 Guarded Optional Dependencies

```python
try:
    import pydantic
except ImportError:
    pydantic = None
```

Always check availability before calling optional libraries, offering graceful degradation or clear user-facing guidance if missing.

---

## 4. Naming Conventions

### 4.1 Identifiers

| Category | Convention | Examples |
| :--- | :--- | :--- |
| **Packages & Modules** | `snake_case` | `config_loader.py`, `service_registry.py` |
| **Classes** | `PascalCase` | `TaskManager`, `HttpRequestHandler` |
| **Abstract Base Classes** | `PascalCase` with `Base` prefix | `BaseAgent`, `BaseRepository` |
| **Dataclasses & Models** | `PascalCase` (noun phrase) | `FindingReport`, `WorkspaceContext` |
| **Enums** | `PascalCase` class, `UPPER_SNAKE` values | `Status.IN_PROGRESS`, `Role.ADMIN` |
| **Functions & Methods** | `snake_case` (verb phrase) | `process_payload()`, `validate_token()` |
| **Internal / Private** | `_leading_underscore` | `_detect_provider()`, `_parse_headers()` |
| **Module Constants** | `UPPER_SNAKE` | `DEFAULT_TIMEOUT_SEC`, `MAX_RETRIES` |
| **Booleans / Flags** | Prefixed with `is_`, `has_`, `can_`, `should_` | `is_valid`, `has_permission`, `can_retry` |

---

## 5. Type Hints & Annotations

### 5.1 Coverage & Style
- Annotate **all** function/method parameters and return types.
- Annotate public attributes on classes and all fields on dataclasses.
- Use generics from the `typing` module (`Dict`, `List`, `Optional`, `Tuple`, `Any`) or modern PEP 604 union types when supported by the project runtime.

```python
from typing import Any, Dict, List, Optional


def fetch_records(
    query: str,
    limit: int = 50,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ...
```

### 5.2 Dynamic & Unstructured Payloads
When working with JSON or loosely structured dictionaries, use `Dict[str, Any]` and access values defensively using `.get()` with typed fallbacks:

```python
name = str(payload.get("name", "unnamed"))
count = int(payload.get("count", 0))
```

---

## 6. Docstrings & Documentation

### 6.1 Docstring Format
Use **Google-style** docstrings across all modules, classes, and non-trivial functions.

### 6.2 Module-Level Docstring
Every Python file must begin with a descriptive docstring summarizing its purpose:

```python
"""
Service Registry & Lifecycle Manager.
Provides dependency resolution and dynamic registration of pluggable service providers.
"""
```

### 6.3 Class & Method Docstrings

```python
class TokenProvider:
    """Manages acquisition, caching, and rotation of authentication tokens."""

    def get_token(self, scope: str, force_refresh: bool = False) -> str:
        """
        Retrieves a valid token for the specified authorization scope.

        Args:
            scope: The OAuth or service scope requested.
            force_refresh: When True, bypasses local cache and fetches a new token.

        Returns:
            A sanitized bearer token string.

        Raises:
            AuthenticationError: If credentials are invalid or expired.
        """
```

---

## 7. Class Design & Data Modeling

### 7.1 Dataclasses for Data Containers
Use `@dataclass` for records, data transfer objects (DTOs), and configuration schemas. Prefer `frozen=True` for immutable entities. Provide `to_dict()` and `from_dict()` methods for JSON-compatible serialization:

```python
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class ServiceRecord:
    """Represents a discovered microservice instance."""
    service_id: str
    endpoint: str
    is_healthy: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize instance to a JSON-safe dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ServiceRecord:
        """Construct instance from dictionary payload."""
        return cls(
            service_id=str(data["service_id"]),
            endpoint=str(data["endpoint"]),
            is_healthy=bool(data.get("is_healthy", True)),
            metadata=dict(data.get("metadata", {})),
        )
```

### 7.2 String Enums
Extend `str, Enum` for all categorical constants to ensure clean JSON serialization and string equality comparison:

```python
from enum import Enum


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
```

### 7.3 Abstract Base Classes (ABCs)
Use `abc.ABC` and `@abc.abstractmethod` to define clear contracts for extensible subsystems and providers:

```python
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseProvider(ABC):
    """Abstract interface for storage and cloud backend providers."""

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to backend."""
        pass

    @abstractmethod
    def read(self, key: str) -> Optional[Dict[str, Any]]:
        """Read value for given key."""
        pass
```

### 7.4 Registry Pattern
Use class-level registries with `@classmethod` methods for dynamic discovery of modules or plugins. Always provide a `clear()` method for test isolation:

```python
class ProviderRegistry:
    _registry: Dict[str, BaseProvider] = {}

    @classmethod
    def register(cls, name: str, provider: BaseProvider) -> None:
        cls._registry[name] = provider

    @classmethod
    def get(cls, name: str) -> Optional[BaseProvider]:
        return cls._registry.get(name)

    @classmethod
    def clear(cls) -> None:
        """Clear registered instances for test isolation."""
        cls._registry.clear()
```

---

## 8. Logging & Observability

### 8.1 Logger Instantiation
Always instantiate loggers at the module level using `logging.getLogger(__name__)` or a specific hierarchical namespace:

```python
import logging

logger = logging.getLogger(__name__)
```

### 8.2 Logging Guidelines

- **Use `%s` Placeholders**: Do **not** use f-strings inside logger calls. Standard `%s` placeholders allow loggers to defer string interpolation until the message is confirmed to meet the log level threshold.
  ```python
  # Correct:
  logger.info("Processed record %s in %0.2f seconds", record_id, elapsed)

  # Incorrect:
  logger.info(f"Processed record {record_id} in {elapsed:0.2f} seconds")
  ```

- **Stdio Isolation for CLI/MCP**: If writing a command-line tool or JSON-RPC / MCP server that communicates over `stdout`, always direct logging output to `sys.stderr` so that standard output remains uncorrupted:
  ```python
  logging.basicConfig(stream=sys.stderr, level=logging.INFO)
  ```

- **Tracebacks**: Use `logger.exception("...")` or pass `exc_info=True` when catching errors in `except` blocks.

- **Sensitive Data**: Never log passwords, API tokens, authorization headers, or customer PII. Implement a token masking helper (`mask_secret()`) for debug output.

---

## 9. Error Handling & Resilience

### 9.1 Exception Hierarchies
- Create custom domain exceptions by subclassing built-in `Exception`:
  ```python
  class ApplicationError(Exception):
      """Base error for application exceptions."""
      pass


  class ConfigurationError(ApplicationError):
      """Raised when configuration values are missing or invalid."""
      pass
  ```
- Use standard built-in exceptions where applicable:
  - `ValueError`: Invalid argument, bad formatting, or validation failure.
  - `TypeError`: Unexpected object type.
  - `KeyError`: Missing required dictionary or collection key.
  - `RuntimeError`: Unrecoverable runtime or system failure.

### 9.2 Defensive Exception Handling
- **Never Use Bare `except:`**: Always specify the exception type (`except Exception:` at minimum).
- **Preserve Error Chains**: Use `raise ... from exc` to maintain the root cause traceback.
- **Fail Gracefully**: For secondary or optional tasks (notifications, metrics, cache lookups), catch non-fatal errors, log a warning, and proceed without crashing the main workflow.

---

## 10. Configuration & Secrets Management

### 10.1 Environment-Based Configuration
- Rely on environment variables with sensible defaults for 12-factor application compatibility:
  ```python
  PORT = int(os.getenv("PORT", "8080"))
  LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
  ```
- Support parsing `.env` files for local development.

### 10.2 Type Coercion Helpers
Use resilient helpers for converting environment string flags into boolean or list values:

```python
def parse_bool(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")
```

### 10.3 Token Masking & URL Sanitization
Always mask secrets before printing or logging:

```python
def mask_token(token: Optional[str]) -> str:
    if not token:
        return "<none>"
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}...{token[-4:]}"
```

---

## 11. Testing Conventions

### 11.1 Framework & Organization
- Use `unittest` (standard library) or `pytest` based on the project configuration.
- Structure test suites inside a `tests/` directory with file names matching `test_<target_module>.py`.
- Class names must follow `Test<Subject>` and test methods must follow `test_<behavior_or_scenario>`.

### 11.2 AAA Pattern (Arrange, Act, Assert)

```python
import unittest


class TestAccountService(unittest.TestCase):

    def setUp(self):
        # Arrange
        self.service = AccountService()

    def test_deposit_increases_balance(self):
        # Act
        new_balance = self.service.deposit(amount=100.0)

        # Assert
        self.assertEqual(new_balance, 100.0)
```

### 11.3 Fixture Isolation & Cleanup
- Always isolate tests using ephemeral workspaces (e.g., `tempfile.mkdtemp(prefix="test_run_")`).
- Clean up created temporary files or directories in `tearDown()` or fixture finalizers using `shutil.rmtree(path, ignore_errors=True)`.
- Isolate shared state (e.g., reset registries or environment overrides) in `tearDown()`.

---

## 12. Architectural Design & Boundaries

### 12.1 Unidirectional Dependencies
Architect systems with clean layer separation. Dependencies must flow downward and inward:

```
Interfaces / CLI / Web / API Handlers
                 ↓
      Orchestration / Workflows
                 ↓
       Domain Services / Agents
                 ↓
      Data Models / Core Utilities
```

- High-level modules may depend on low-level abstractions, but low-level domain models must **never** import from CLI, web handlers, or orchestration layers.
- Modules should interact via abstract interfaces rather than tight concrete coupling.

### 12.2 Package Boundaries & `__all__`
- Keep package roots clean. Re-export key public interfaces in `__init__.py` and explicitly define `__all__`:
  ```python
  from .client import ApiClient
  from .models import RequestModel, ResponseModel

  __all__ = [
      "ApiClient",
      "RequestModel",
      "ResponseModel",
  ]
  ```

---

## 13. Summary Checklist for Code Reviews

Before committing code or submitting a Pull Request, verify:

- [ ] Does every new module begin with `from __future__ import annotations` and a descriptive docstring?
- [ ] Are all functions and method signatures fully type-annotated?
- [ ] Are imports categorized into the 4 standard blocks (future, stdlib, 3rd-party, local)?
- [ ] Are external dependencies optional or standard-library-first?
- [ ] Are dataclasses used for structured records and models, with `to_dict()` / `from_dict()` where appropriate?
- [ ] Are enums subclassing `(str, Enum)` for direct serializability?
- [ ] Does logging use `%s` placeholders rather than f-strings?
- [ ] Are sensitive tokens or credentials masked before logging or output?
- [ ] Are temporary files properly cleaned up in test `tearDown()` methods?
- [ ] Does the test suite pass cleanly without reliance on external network calls?
