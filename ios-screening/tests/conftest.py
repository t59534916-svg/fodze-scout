import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_ROOT, os.path.join(_ROOT, "samples")):
    if p not in sys.path:
        sys.path.insert(0, p)
