"""FastAPI layer. Thin on purpose: it validates input, calls `stego_core`, and
shapes the response. No steganography or cryptography logic belongs here.
"""
