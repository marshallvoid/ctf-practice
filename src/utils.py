import re
import shutil
import subprocess
import sys
from typing import Any, Callable, List, Optional, Tuple, cast


def run_prefixed_functions(
    namespace: dict[str, Any],
    prefix: str,
    *,
    label: Optional[str] = None,
    copy_last: bool = True,
) -> Optional[str]:
    """Discover and run functions named like "{prefix}{number}" in the given namespace.

    - Sorts by numeric suffix
    - Prints each normalized flag as: "Flag {label or prefix} {number}: ..."
    - Copies the last normalized flag to clipboard if copy_last is True
    - Returns the last normalized flag (or None if none found)
    """
    pattern = re.compile(rf"{re.escape(prefix)}(\d+)$")

    functions: List[Tuple[int, Callable[[], str]]] = []
    for name, obj in namespace.items():
        match = pattern.fullmatch(name)
        if match and callable(obj):
            number = int(match.group(1))
            functions.append((number, cast(Callable[[], str], obj)))

    last_flag: Optional[str] = None
    for number, func in sorted(functions, key=lambda t: t[0]):
        try:
            result = func()
        except Exception as exc:  # keep going even if one function fails
            result = f"Error: {exc}"

        normalized = normalize_flag(result)
        printed_label = label if label is not None else prefix
        print(f"Flag {printed_label} {number}: {normalized}")
        last_flag = normalized

    if copy_last and last_flag:
        copy_to_clipboard(last_flag)

    return last_flag


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard. Returns True on success.

    - macOS: uses pbcopy
    - Linux: tries xclip then xsel
    - Windows: uses clip
    """
    try:
        if sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text, text=True, check=True)
            print("[copied to clipboard]")
            return True

        if sys.platform.startswith("linux"):
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=text, text=True, check=True)
                print("[copied to clipboard]")
                return True

            if shutil.which("xsel"):
                subprocess.run(["xsel", "--clipboard", "--input"], input=text, text=True, check=True)
                print("[copied to clipboard]")
                return True

            return False

        if sys.platform.startswith("win"):
            subprocess.run(["clip"], input=text, text=True, check=True)
            print("[copied to clipboard]")
            return True

    except Exception:
        pass

    return False


def normalize_flag(value: str) -> str:
    text = value.strip()
    if re.fullmatch(r"crypto\{.*\}", text):
        return text

    # Heuristic: if it contains whitespace/newlines, likely not a bare flag payload
    if re.search(r"\s", text):
        return text

    return f"crypto{{{text}}}"
