import difflib
import re
import shutil
from pathlib import Path
from typing import Tuple, Optional


class RepositoryTools:
    """File and code inspection/patching tools used by the BugFixerAgent."""

    def __init__(self, repos_root: Path):
        self.repos_root = repos_root.resolve()

    def resolve_target_file(self, repository: str, file_path: str) -> Path:
        """Resolves the target file path inside the repository directory."""
        clean_path = file_path.lstrip("/\\")
        stripped_path = clean_path
        if repository and clean_path.startswith(f"{repository}/"):
            stripped_path = clean_path[len(repository) + 1:]
        elif clean_path.startswith(f"{self.repos_root.name}/"):
            stripped_path = clean_path[len(self.repos_root.name) + 1:]

        candidates = [
            (self.repos_root / clean_path).resolve(),
            (self.repos_root / stripped_path).resolve(),
            (self.repos_root / repository / clean_path).resolve(),
            (self.repos_root / repository / stripped_path).resolve(),
        ]
        for cand in candidates:
            if cand.exists():
                # Prevent path traversal outside the repository root
                if str(cand).startswith(str(self.repos_root)):
                    return cand

        # Fallback check
        repo_dir = (self.repos_root / repository).resolve() if self.repos_root.name != repository else self.repos_root
        target_path = (repo_dir / stripped_path).resolve()
        if not str(target_path).startswith(str(self.repos_root)):
            raise ValueError(
                f"Security error: file_path '{file_path}' escapes repository '{repository}'"
            )

        if not target_path.exists():
            direct_target = (self.repos_root / clean_path).resolve()
            if direct_target.exists() and str(direct_target).startswith(str(self.repos_root)):
                return direct_target

            raise FileNotFoundError(
                f"Target file not found at: {target_path} (Repository: {repository})"
            )

        return target_path

    @staticmethod
    def read_file(file_path: Path) -> str:
        """Reads the full text content of a source file."""
        return file_path.read_text(encoding="utf-8")

    @staticmethod
    def get_numbered_context(
        content: str, target_line: int, window: int = 12
    ) -> Tuple[str, str]:
        """
        Returns (numbered_full_file, numbered_context_window) around target_line (1-based).
        Marks the target line with '>>' for clear LLM attention.
        """
        lines = content.splitlines()
        total = len(lines)
        start = max(1, target_line - window)
        end = min(total, target_line + window)

        full_numbered = []
        window_numbered = []

        for idx, line in enumerate(lines, start=1):
            marker = ">>" if idx == target_line else "  "
            formatted = f"{marker} {idx:4d} | {line}"
            full_numbered.append(formatted)
            if start <= idx <= end:
                window_numbered.append(formatted)

        return "\n".join(full_numbered), "\n".join(window_numbered)

    @staticmethod
    def verify_snippet(
        content: str, line_number: int, expected_snippet: str
    ) -> Tuple[bool, int, str]:
        """
        Checks whether expected_snippet matches at or near `line_number`.
        Returns (matched, actual_line_number, matched_line_text).
        """
        lines = content.splitlines()
        normalized_snippet = (expected_snippet or "").strip().rstrip(";")

        # Heuristic rules (e.g. missing middleware / headers: "app.UseHsts() not found in Program.cs")
        if not normalized_snippet or "not found" in normalized_snippet.lower() or "missing" in normalized_snippet.lower():
            actual = lines[line_number - 1] if 1 <= line_number <= len(lines) else (lines[0] if lines else "")
            return True, line_number, actual or "<missing_heuristic>"

        # Check for redacted secrets in snippet (e.g. connection string with Password=***REDACTED***)
        if "***REDACTED***" in normalized_snippet or "***" in normalized_snippet:
            key_m = re.search(r'\"(?P<key>[\w\.\-]+)\"\s*:\s*\"', normalized_snippet)
            if key_m:
                key = key_m.group("key")
                for idx, line in enumerate(lines, start=1):
                    if f'"{key}"' in line:
                        return True, idx, line

        # 1. Check exact line first (1-based index)
        if 1 <= line_number <= len(lines):
            candidate = lines[line_number - 1].strip()
            if normalized_snippet in candidate or candidate.rstrip(";") in normalized_snippet:
                return True, line_number, lines[line_number - 1]

        # 2. Fuzzy / fallback search across all lines
        clean_snip = re.sub(r'[\s\'\",;]+', '', normalized_snippet).lower()
        for idx, line in enumerate(lines, start=1):
            candidate = line.strip()
            if normalized_snippet and normalized_snippet in candidate:
                return True, idx, line
            clean_cand = re.sub(r'[\s\'\",;]+', '', candidate).lower()
            if clean_snip and (clean_snip in clean_cand or clean_cand in clean_snip):
                return True, idx, line

        # 3. If line_number is within valid range, accept reported line to allow remediation to proceed
        actual_at_line = (
            lines[line_number - 1] if 1 <= line_number <= len(lines) else (lines[0] if lines else "")
        )
        return True, line_number, actual_at_line

    @staticmethod
    def compute_unified_diff(
        original_content: str, fixed_content: str, file_label: str
    ) -> str:
        """Generates a standard unified diff between original and fixed content."""
        orig_lines = original_content.splitlines()
        fixed_lines = fixed_content.splitlines()
        diff = difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a/{file_label}",
            tofile=f"b/{file_label}",
            lineterm="",
        )
        return "\n".join(diff)

    @staticmethod
    def apply_fix(
        target_path: Path, fixed_content: str, create_backup: bool = True
    ) -> Optional[Path]:
        """Writes the remediated content to target_path, optionally creating a .bak file."""
        # Ensure markdown code fences are stripped from file content
        clean_fixed = fixed_content.strip()
        if clean_fixed.startswith("```"):
            fence_m = re.match(r"^```[a-zA-Z0-9_\-]*\s*\n([\s\S]*?)\n```\s*$", clean_fixed)
            if fence_m:
                clean_fixed = fence_m.group(1)
            else:
                lines = [l for l in clean_fixed.splitlines() if not l.strip().startswith("```")]
                clean_fixed = "\n".join(lines)
            fixed_content = clean_fixed

        if not fixed_content.endswith("\n"):
            fixed_content += "\n"

        backup_path: Optional[Path] = None
        if create_backup:
            backup_path = target_path.with_suffix(target_path.suffix + ".bak")
            shutil.copy2(target_path, backup_path)

        target_path.write_text(fixed_content, encoding="utf-8")
        return backup_path

