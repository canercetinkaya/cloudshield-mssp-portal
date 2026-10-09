"""
Zero SOC & Ticket Isolation Guardrail
CloudShield Security Reporting Platform kurali geregi, SOC veya biletleme kalintilarinin
kod tabaninda yer almasini engeller.
"""
import os
import sys

# Parcalanmis desen tanimlari (kendi kendini eslememesi icin)
p1 = "(" + "SOC" + ")"
p2 = "SVC-" + "SOC"
patterns = [p1, p2]

skip_exts = {".md", ".txt", ".yml", ".yaml", ".pyc"}
skip_files = {"verify_zero_soc.py"}
hits = []

for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", "docs", "brain", ".gemini"}]
    for fname in files:
        if fname in skip_files or any(fname.endswith(e) for e in skip_exts):
            continue
        fpath = os.path.join(root, fname)
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh, 1):
                    for p in patterns:
                        if p in line:
                            hits.append(f"{fpath}:{i}: {line.rstrip()}")
        except Exception:
            pass

if hits:
    print("HATA: Kod tabaninda yetkisiz SOC ifadesi bulundu!")
    for h in hits:
        print(h)
    sys.exit(1)
else:
    print("Zero SOC Kurali Dogrulandi: Ihlal Yok.")
