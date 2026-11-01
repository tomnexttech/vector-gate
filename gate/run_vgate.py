# -*- coding: utf-8 -*-
"""Run vgate without installing it:  python -I run_vgate.py hook|status|verify|stop|resume|check|settings

-I keeps PYTHONPATH and the user site out; this file puts its own folder on sys.path instead.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vector_gate.cli import main  # noqa: E402

sys.exit(main())
