#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecuPredict Monitor 0.3.0 entry point.

Usage:
  python secupredict_monitor.py                       # clinic profile, port 8080
  python secupredict_monitor.py --demo                # 60-second deterministic demo, offline
  python secupredict_monitor.py --profile online_shop
  python secupredict_monitor.py --enforce             # really perform response actions
  python secupredict_monitor.py --agent --server http://IP:8080 --agent-key KEY
  python secupredict_monitor.py --report report.html  # one-page report from the database

All code lives in the `secupredict` package; see README.md.
"""
import sys

from secupredict.app import main

if __name__ == "__main__":
    sys.exit(main())
