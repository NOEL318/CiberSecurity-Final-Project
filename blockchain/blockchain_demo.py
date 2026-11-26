#!/usr/bin/env python3
"""
LIS4062 Final Project - Part 3: Blockchain and Bitcoin using hash functions.

Run:  python blockchain_demo.py        (Python 3.8+, standard library only)

What it shows
  1. SHA-256 properties: fixed size, determinism, avalanche effect.
  2. A minimal blockchain: blocks linked by the hash of the previous header,
     transactions summarised by a Merkle root, Proof-of-Work mining.
  3. Mining cost grows ~16x per extra leading hex zero (difficulty).
  4. Tamper detection: editing one old transaction breaks every later link.
  5. Merkle proof: proving that one transaction is inside a block with log2(n) hashes.
  6. REAL Bitcoin data: recomputing the hash of Bitcoin's genesis block (3 Jan 2009)
     with double SHA-256 and checking it against the difficulty target, and deriving
     Satoshi's first address from its public key with SHA-256 + RIPEMD-160 + Base58Check.
"""
import hashlib
import json
import struct
import sys
import time


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def dsha256(b: bytes) -> bytes:  # Bitcoin uses SHA-256 applied twice
    return sha256(sha256(b))


def bits_diff(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# ---------------------------------------------------------------- Merkle tree
def merkle_root(tx_hashes):
    level = list(tx_hashes)
    if not level:
        return b"\x00" * 32
    while len(level) > 1:
        if len(level) % 2:  # Bitcoin duplicates the last hash on odd levels
            level.append(level[-1])
        level = [dsha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(tx_hashes, index):
    """Returns the list of (sibling_hash, sibling_is_right) needed to rebuild the root."""
    proof, level, i = [], list(tx_hashes), index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = i ^ 1
        proof.append((level[sib], sib > i))
        level = [dsha256(level[k] + level[k + 1]) for k in range(0, len(level), 2)]
        i //= 2
    return proof


def verify_proof(tx_hash, proof, root):
    h = tx_hash
    for sib, right in proof:
        h = dsha256(h + sib) if right else dsha256(sib + h)
    return h == root


# ---------------------------------------------------------------- Blocks
class Block:
    def __init__(self, index, prev_hash, transactions, difficulty, timestamp=None):
        self.index = index
        self.prev_hash = prev_hash
        self.transactions = transactions
        self.difficulty = difficulty  # number of leading zero HEX digits required
        self.timestamp = int(timestamp if timestamp is not None else time.time())
        self.nonce = 0
        self.hash = None

    def tx_hashes(self):
        return [dsha256(json.dumps(t, sort_keys=True).encode()) for t in self.transactions]

    def header(self):
        return (struct.pack("<I", self.index) + self.prev_hash + merkle_root(self.tx_hashes())
                + struct.pack("<I", self.timestamp) + struct.pack("<I", self.difficulty)
                + struct.pack("<Q", self.nonce))

    def compute_hash(self):
        return dsha256(self.header()).hex()

    def mine(self):
        target = "0" * self.difficulty
        t0 = time.perf_counter()
        self.nonce = 0
        while True:
            h = self.compute_hash()
            if h.startswith(target):
                self.hash = h
                return self.nonce + 1, time.perf_counter() - t0
            self.nonce += 1


def validate_chain(chain):
    problems = []
    for i, b in enumerate(chain):
        if b.compute_hash() != b.hash:
            problems.append(f"block {i}: stored hash does not match its contents")
        if not b.hash.startswith("0" * b.difficulty):
            problems.append(f"block {i}: proof-of-work missing")
        if i > 0 and b.prev_hash.hex() != chain[i - 1].hash:
            problems.append(f"block {i}: prev_hash does not point to block {i - 1}")
    return problems


# ---------------------------------------------------------------- Real Bitcoin data
def bitcoin_genesis():
    version = 1
    prev = bytes(32)
    merkle_be = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    timestamp = 1231006505  # 2009-01-03 18:15:05 UTC
    bits = 0x1D00FFFF
    nonce = 2083236893
    header = (struct.pack("<I", version) + prev + bytes.fromhex(merkle_be)[::-1]
              + struct.pack("<I", timestamp) + struct.pack("<I", bits) + struct.pack("<I", nonce))
    h = dsha256(header)[::-1].hex()  # Bitcoin displays hashes byte-reversed
    exponent, mantissa = bits >> 24, bits & 0xFFFFFF
    target = mantissa * (1 << (8 * (exponent - 3)))
    return {
        "header_bytes": len(header),
        "header_hex": header.hex(),
        "computed_hash": h,
        "expected_hash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "target": f"{target:064x}",
        "hash_below_target": int(h, 16) < target,
        "leading_zero_bits": 256 - int(h, 16).bit_length(),
        "nonce": nonce,
        "time_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp)),
    }


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload: bytes) -> str:
    data = payload + dsha256(payload)[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def ripemd160(b: bytes):
    try:
        return hashlib.new("ripemd160", b).digest()
    except (ValueError, TypeError):
        return None  # some OpenSSL 3 builds disable RIPEMD-160


def genesis_address():
    # Public key (secp256k1, uncompressed) paid by the genesis coinbase transaction
    pub = bytes.fromhex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
                        "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
    h1 = sha256(pub)
    h160 = ripemd160(h1)
    if h160 is None:
        return {"available": False}
    addr = base58check(b"\x00" + h160)
    return {"available": True, "pubkey_bytes": len(pub), "sha256": h1.hex(), "hash160": h160.hex(),
            "address": addr, "expected": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}


# ---------------------------------------------------------------- main
def main():
    results = {}
    line = "-" * 78
    print(line + "\n1) SHA-256 properties\n" + line)
    m1, m2 = b"Transfer 10 BTC to Alice", b"Transfer 10 BTC to Alicf"
    h1, h2 = sha256(m1), sha256(m2)
    flipped = bits_diff(h1, h2)
    print(f"SHA-256('{m1.decode()}') = {h1.hex()}")
    print(f"SHA-256('{m2.decode()}') = {h2.hex()}")
    print(f"One character changed -> {flipped}/256 output bits flipped ({flipped / 2.56:.1f}%)")
    big = sha256(b"x" * 1_000_000)
    print(f"1 MB input still gives a 256-bit digest: {big.hex()[:32]}...")
    # average avalanche over many single-bit changes
    tot = 0
    for i in range(256):
        base = bytearray(b"LIS4062 blockchain avalanche test 2026")
        base2 = bytearray(base)
        base2[i % len(base2)] ^= 1 << (i % 8)
        tot += bits_diff(sha256(bytes(base)), sha256(bytes(base2)))
    avg = tot / 256
    print(f"Average over 256 single-bit input changes: {avg:.1f} bits flipped (ideal 128)")
    results["avalanche"] = {"m1": m1.decode(), "m2": m2.decode(), "h1": h1.hex(), "h2": h2.hex(),
                            "bits_flipped": flipped, "avg_bits_flipped_256_trials": avg}

    print("\n" + line + "\n2) Mining a small blockchain (Proof-of-Work, difficulty = 4 hex zeros)\n" + line)
    ts = 1764000000
    txs = [
        [{"from": "coinbase", "to": "Miner-A", "amount": 3.125}],
        [{"from": "Alice", "to": "Bob", "amount": 1.5}, {"from": "Bob", "to": "Carol", "amount": 0.4},
         {"from": "Carol", "to": "Dave", "amount": 0.1}],
        [{"from": "Dave", "to": "Alice", "amount": 0.05}, {"from": "Alice", "to": "Eve", "amount": 0.7}],
        [{"from": "Eve", "to": "Bob", "amount": 0.2}],
    ]
    chain = []
    prev = bytes(32)
    rows = []
    for i, t in enumerate(txs):
        b = Block(i, prev, t, 4, timestamp=ts + 600 * i)
        tries, secs = b.mine()
        chain.append(b)
        prev = bytes.fromhex(b.hash)
        rows.append({"block": i, "txs": len(t), "nonce": b.nonce, "tries": tries, "seconds": round(secs, 3),
                     "merkle_root": merkle_root(b.tx_hashes()).hex(), "hash": b.hash,
                     "prev_hash": b.prev_hash.hex()})
        print(f"Block {i}: {len(t)} tx  nonce={b.nonce:>7}  hash={b.hash}")
        print(f"         prev={b.prev_hash.hex()}")
    print("Chain valid:", not validate_chain(chain))
    results["chain"] = rows

    print("\n" + line + "\n3) Cost of Proof-of-Work vs difficulty (same block, 5 trials each)\n" + line)
    pow_rows = []
    for d in range(1, 6):
        tries_l, secs_l = [], []
        trials = 5
        for k in range(trials):
            b = Block(99, bytes(32), [{"from": "A", "to": "B", "amount": k, "trial": d}], d, timestamp=ts + k)
            tries, secs = b.mine()
            tries_l.append(tries)
            secs_l.append(secs)
        avg_t, avg_s = sum(tries_l) / trials, sum(secs_l) / trials
        pow_rows.append({"difficulty_hex_zeros": d, "expected_tries": 16 ** d, "avg_tries": avg_t,
                         "avg_seconds": avg_s})
        print(f"difficulty {d} ({4 * d:2d} zero bits): expected 16^{d} = {16 ** d:>8,} tries, "
              f"measured avg {avg_t:>10,.0f} tries, {avg_s:8.3f} s")
    results["pow"] = pow_rows

    print("\n" + line + "\n4) Tamper detection\n" + line)
    original = chain[1].transactions[0]["amount"]
    chain[1].transactions[0]["amount"] = 150.0  # attacker edits Alice->Bob from 1.5 to 150
    probs = validate_chain(chain)
    new_root = merkle_root(chain[1].tx_hashes()).hex()
    print(f"Changed block 1, tx 0 amount {original} -> 150.0")
    print(f"Merkle root  before: {rows[1]['merkle_root']}")
    print(f"Merkle root  after : {new_root}")
    print(f"Block 1 hash after : {chain[1].compute_hash()}  (stored {chain[1].hash})")
    for p in probs:
        print("  INVALID ->", p)
    remine_tries = sum(16 ** 4 for _ in range(1, len(chain)))
    print(f"To hide the edit the attacker must re-mine blocks 1..{len(chain) - 1} "
          f"(~{remine_tries:,} hashes here) faster than the honest network extends the chain.")
    results["tamper"] = {"original_amount": original, "new_amount": 150.0, "root_before": rows[1]["merkle_root"],
                         "root_after": new_root, "problems": probs}
    chain[1].transactions[0]["amount"] = original

    print("\n" + line + "\n5) Merkle proof (simplified payment verification)\n" + line)
    many = [{"id": i, "from": f"user{i}", "to": f"user{i + 1}", "amount": i / 10} for i in range(8)]
    hashes = [dsha256(json.dumps(t, sort_keys=True).encode()) for t in many]
    root = merkle_root(hashes)
    proof = merkle_proof(hashes, 5)
    ok = verify_proof(hashes[5], proof, root)
    print(f"8 transactions, root = {root.hex()}")
    print(f"Proof for tx #5 needs {len(proof)} hashes (log2 8 = 3) instead of all 8 -> valid: {ok}")
    results["merkle_proof"] = {"n_tx": 8, "proof_len": len(proof), "valid": ok, "root": root.hex()}

    print("\n" + line + "\n6) REAL Bitcoin: genesis block (block 0)\n" + line)
    g = bitcoin_genesis()
    print(f"80-byte header : {g['header_hex']}")
    print(f"double SHA-256 : {g['computed_hash']}")
    print(f"published hash : {g['expected_hash']}")
    print(f"match          : {g['computed_hash'] == g['expected_hash']}")
    print(f"target (bits 0x1d00ffff) = {g['target']}")
    print(f"hash < target  : {g['hash_below_target']}  ({g['leading_zero_bits']} leading zero bits, "
          f"nonce {g['nonce']:,}, mined {g['time_utc']} UTC)")
    a = genesis_address()
    if a["available"]:
        print(f"Genesis public key -> SHA-256 -> RIPEMD-160 = {a['hash160']}")
        print(f"Base58Check address: {a['address']}  (expected {a['expected']}, match {a['address'] == a['expected']})")
    else:
        print("RIPEMD-160 not available in this Python/OpenSSL build - address step skipped")
    results["genesis"] = g
    results["genesis_address"] = a

    out = sys.argv[1] if len(sys.argv) > 1 else "blockchain_results.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out}")


if __name__ == "__main__":
    main()
