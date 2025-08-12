from src.utils import run_prefixed_functions


def course1() -> str:
    return "modinv_placeholder"


def courses() -> None:
    run_prefixed_functions(globals(), "course", label="mod", copy_last=True)
