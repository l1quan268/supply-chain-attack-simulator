# corp-auth-utils (v99.0.0 — MALICIOUS)

> ⚠️ This is a **malicious PoC package** for academic Dependency Confusion demo.

Looks identical to the legitimate internal `corp-auth-utils` v1.0.0 but contains a hidden payload in `setup.py` that triggers on `pip install`.

## How Dependency Confusion works

1. Company has `corp-auth-utils==1.0.0` on internal registry
2. Attacker publishes `corp-auth-utils==99.0.0` on public PyPI
3. pip picks the higher version → payload executes during install

