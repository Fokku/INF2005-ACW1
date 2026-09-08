"""HTTP routers. Each one validates input, calls `stego_core`, and shapes the
response defined in `app/schemas.py`.

The request plumbing is written. The single line that calls into the core is
marked TODO in each file — that is the only place a router should change.
"""
