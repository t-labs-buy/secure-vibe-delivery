from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..config import ProjectConfig
from ..detect import ProjectInfo
from ..models import RunOptions


@dataclass
class CheckContext:
    root: Path
    run_dir: Path
    info: ProjectInfo
    options: RunOptions
    log: Callable[[str], None] = field(default=lambda m: None)
    config: ProjectConfig = field(default_factory=ProjectConfig)

    @property
    def raw_dir(self) -> Path:
        d = self.run_dir / "raw"
        d.mkdir(parents=True, exist_ok=True)
        return d
