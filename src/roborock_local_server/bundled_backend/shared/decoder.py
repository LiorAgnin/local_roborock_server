"""Roborock decoder bootstrap helpers."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from roborock.protocol import Decoder


def _ensure_local_python_roborock_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    local_python_roborock = repo_root / "python-roborock"
    if local_python_roborock.exists():
        local_path = str(local_python_roborock)
        if local_path not in sys.path:
            sys.path.insert(0, local_path)


def build_decoder(localkey: str) -> tuple[Decoder, dict[int, str]]:
    _ensure_local_python_roborock_on_path()
    try:
        from roborock.protocol import create_mqtt_decoder
        from roborock.roborock_message import RoborockMessageProtocol
    except Exception as exc:  # pragma: no cover - runtime dependency guard
        raise RuntimeError(
            "python-roborock decoder is unavailable. "
            "Install with: pip install -e ../../python-roborock"
        ) from exc

    decoder = create_mqtt_decoder(localkey)
    protocol_names = {
        int(proto.value): proto.name for proto in RoborockMessageProtocol
    }
    return decoder, protocol_names
