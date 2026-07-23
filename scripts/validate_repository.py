from pathlib import Path
import json
import sys

root = Path(__file__).resolve().parents[1]
failures: list[str] = []
for path in root.rglob("*"):
    if not path.is_file() or any(part in {"target", "node_modules", ".git"} for part in path.parts):
        continue
    if path.suffix == ".json":
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append(f"invalid JSON {path.relative_to(root)}: {exc}")
    if path.stat().st_size > 5_000_000:
        failures.append(f"oversized source artifact {path.relative_to(root)}")

forbidden = ["dev-secret-change-me", "MINISIGN_ROOT_SECRET"]
for path in root.rglob("*"):
    if path.resolve() == Path(__file__).resolve():
        continue
    if path.is_file() and path.suffix.lower() in {
        ".py", ".rs", ".ts", ".js", ".mjs", ".yml", ".yaml", ".json", ".md", ".toml"
    }:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in forbidden:
            if needle in text:
                failures.append(f"forbidden token {needle!r} in {path.relative_to(root)}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)
print("repository validation passed")
