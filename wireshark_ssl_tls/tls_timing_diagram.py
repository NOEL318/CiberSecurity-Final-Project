#!/usr/bin/env python3
"""
Draws the client-server timing diagram requested in Question 1 of the SSL/TLS lab:
one arrow per SSL/TLS record for the first 8 Ethernet frames of YOUR Wireshark trace.

1) Edit the FRAMES list below with what you see in Wireshark (filter: tls).
   Each entry: (wireshark_frame_number, "C" or "S" = who sent it, [list of record types in the frame])
2) Run:  python tls_timing_diagram.py      (needs: pip install matplotlib)
3) Insert timing_diagram.png in the report as the figure "timing diagram".
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---------------- EDIT THIS WITH YOUR OWN TRACE ----------------
FRAMES = [
    # EXAMPLE of a typical TLS 1.3 browser trace - REPLACE with your values
    (5,  "C", ["Handshake: Client Hello"]),
    (8,  "S", ["Handshake: Server Hello", "Change Cipher Spec", "Application Data (encrypted handshake)"]),
    (10, "S", ["Application Data (encrypted handshake, cont.)"]),
    (12, "C", ["Change Cipher Spec", "Application Data (encrypted Finished)"]),
    (13, "C", ["Application Data (HTTP request)"]),
    (16, "S", ["Application Data (New Session Ticket)"]),
    (17, "S", ["Application Data (HTTP response)"]),
    (19, "C", ["Application Data"]),
]
CLIENT_LABEL = "Client (our host)"
SERVER_LABEL = "Server (e-commerce site)"
OUTPUT = "timing_diagram.png"
# ---------------------------------------------------------------

n_arrows = sum(len(r) for _, _, r in FRAMES)
fig_h = 1.2 + 0.42 * n_arrows
fig, ax = plt.subplots(figsize=(7.5, fig_h))
xc, xs = 0.15, 0.85
top, step = n_arrows + 0.5, 1.0
ax.plot([xc, xc], [0, top + 0.3], color="#52514e", lw=2)
ax.plot([xs, xs], [0, top + 0.3], color="#52514e", lw=2)
ax.text(xc, top + 0.6, CLIENT_LABEL, ha="center", fontsize=10, fontweight="bold")
ax.text(xs, top + 0.6, SERVER_LABEL, ha="center", fontsize=10, fontweight="bold")

y = top
for frame, src, records in FRAMES:
    color = "#2a78d6" if src.upper() == "C" else "#1baf7a"
    first = True
    for rec in records:
        y -= step
        x0, x1 = (xc, xs) if src.upper() == "C" else (xs, xc)
        ax.annotate("", xy=(x1, y - 0.35), xytext=(x0, y),
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=1.6))
        ax.text(0.5, y - 0.1, rec, ha="center", va="bottom", fontsize=8.5,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"))
        if first:
            ax.text(0.01 if src.upper() == "C" else 0.99, y - 0.15, f"frame {frame}",
                    ha="left" if src.upper() == "C" else "right", fontsize=8, color="#52514e")
            first = False
ax.set_xlim(0, 1)
ax.set_ylim(y - 0.8, top + 1.0)
ax.axis("off")
fig.tight_layout()
fig.savefig(OUTPUT, dpi=200)
print("saved", OUTPUT)
