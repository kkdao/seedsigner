"""
Silent Payments (BIP-352) receive keys, for exporting a scan-only wallet, and
signing spends of received payments (BIP-376).

The Seed options export needs the account's address, and its private scan key in
the form Sparrow imports. There are no labels. The spend private key, and each
output key derived from it, never leaves this module.

TODO: move this into embit once embit ships Silent Payments support (0.8.0 has
none).
"""
from io import BytesIO

from embit import bech32, compact, ec, hashes
from embit.bip32 import HARDENED_INDEX as H
from embit.transaction import SIGHASH
from embit.util import key as pykey, secp256k1

from seedsigner.models.settings_definition import SettingsConstants


# BIP-352 coin types. Regtest is left out on purpose: wallets don't agree on its
# address prefix (Sparrow uses "sprt"), so the export is offered on mainnet and
# testnet only.
COIN_TYPES = {SettingsConstants.MAINNET: 0, SettingsConstants.TESTNET: 1}

# PSBT key types. BIP-375 (sending to a Silent Payment address) by scope, and
# BIP-376's per-input spend fields. embit knows none of them, so they sit in each
# scope's `unknown` map, and so does the PSBT_IN_TAP_KEY_SIG a spend is answered with.
SEND_KEY_TYPES = {"global": (0x07, 0x08), "input": (0x1D, 0x1E), "output": (0x09, 0x0A)}
IN_SP_SPEND_BIP32_DERIVATION = 0x1F
IN_SP_TWEAK = 0x20
IN_TAP_KEY_SIG = b"\x13"
IN_PARTIAL_SIG = b"\x02"
IN_SIGHASH_TYPE = b"\x03"
GLOBAL_TX_MODIFIABLE = b"\x06"
OUT_SCRIPT = b"\x04"

# BIP-352's limit on payments sharing one scan key, which bounds a receiver's scan.
K_MAX = 2323

# The secp256k1 group order.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Where the bytes a psbt was parsed from are kept, on the psbt itself.
_OWN_BYTES = "_sp_own_bytes"


def _master_root(seed, network: str):
    """The seed's BIP-32 master key. Raises ValueError if it can't export here."""
    if network not in COIN_TYPES:
        raise ValueError("Silent Payments needs mainnet or testnet")
    if seed.script_override:
        # Electrum and Aezeed seeds are pinned to a single script type.
        raise ValueError("This seed type has no Silent Payments account")
    root = seed.get_root(network)
    if root.depth != 0:
        # Below the master, both the fingerprint and the m/352' path would be wrong.
        raise ValueError("Silent Payments needs a master key, not a derived xprv")
    return root


def is_supported(seed, network: str) -> bool:
    try:
        _master_root(seed, network)
    except ValueError:
        return False
    return True


def derivation_path(network: str) -> str:
    return "m/352'/%d'/0'" % COIN_TYPES[network]


def _keys(seed, network: str):
    """The (scan, spend) private keys: m/352'/coin'/0'/1'/0 and m/352'/coin'/0'/0'/0."""
    account = _master_root(seed, network).derive([H + 352, H + COIN_TYPES[network], H + 0])
    return account.derive([H + 1, 0]).key, account.derive([H + 0, 0]).key


def _bech32m(hrp: str, payload: bytes) -> str:
    # embit's bech32.encode() only does segwit programs (bech32 for v0, up to 40
    # bytes), so build the data part here: version 0, then the payload in 5-bit groups.
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [0] + bech32.convertbits(payload, 8, 5))


def address(seed, network: str) -> str:
    """The account's sp1... address (tsp1... on testnet), without labels."""
    scan, spend = _keys(seed, network)
    hrp = "sp" if network == SettingsConstants.MAINNET else "tsp"
    return _bech32m(hrp, scan.sec() + spend.sec())


def scan_key_export(seed, network: str) -> str:
    """
    The account's private scan key as Sparrow's SeedSigner import reads it:
    "[fingerprint/352h/coinh/0h]spscan1...", a BIP-392 key expression with its
    origin (Sparrow adds the sp(...) itself). It can't spend, but whoever holds it
    sees every payment to this wallet.
    """
    scan, spend = _keys(seed, network)
    hrp = "spscan" if network == SettingsConstants.MAINNET else "tspscan"
    return "[%s/352h/%dh/0h]%s" % (
        seed.get_fingerprint(network),
        COIN_TYPES[network],
        _bech32m(hrp, scan.secret + spend.sec()),
    )



def _has_key_type(scope, key_types) -> bool:
    return any(key[0] in key_types for key in scope.unknown)


def has_send_fields(psbt) -> bool:
    """Whether any map carries a BIP-375 field."""
    return (_has_key_type(psbt, SEND_KEY_TYPES["global"])
            or any(_has_key_type(inp, SEND_KEY_TYPES["input"]) for inp in psbt.inputs)
            or any(_has_key_type(out, SEND_KEY_TYPES["output"]) for out in psbt.outputs))


def is_spend_input(inp) -> bool:
    """Whether an input carries any BIP-376 field, well-formed or not."""
    return _has_key_type(inp, (IN_SP_SPEND_BIP32_DERIVATION, IN_SP_TWEAK))


def remember_bytes(psbt, raw: bytes):
    """
    Keep the bytes a psbt arrived as, at the point it is parsed, if it is a BIP-376
    spend.

    embit writes each map's fields in its own order and fills in defaults it read
    nothing for, so re-serializing a psbt does not give back the bytes it came in
    as. A BIP-376 answer has to: the coordinator compares the response against the
    request field by field. See splice_signatures.

    Only a Silent Payment psbt, so that no other flow's export changes, and so a large
    psbt read from a card is not held twice for nothing. A send (BIP-375) needs it as
    much as a spend: its response is the request plus the scripts, proofs and
    signatures this device adds.
    """
    if any(is_spend_input(inp) for inp in psbt.inputs) or has_send_fields(psbt):
        setattr(psbt, _OWN_BYTES, bytes(raw))


def has_own_bytes(psbt) -> bool:
    return getattr(psbt, _OWN_BYTES, None) is not None


def psbt_bytes(psbt) -> bytes:
    """The bytes this psbt arrived as (or was signed into), else embit's serialization."""
    return getattr(psbt, _OWN_BYTES, None) or psbt.serialize()


def _maps(raw: bytes) -> list:
    """
    Each key-value map of a serialized psbt, as (fields, the offset of its terminator,
    the records in the order they were written as (key, value, start, end)).
    """
    stream = BytesIO(raw)
    if stream.read(5) != b"psbt\xff":
        raise ValueError("not a psbt")
    maps, fields, records = [], {}, []
    while stream.tell() < len(raw):
        start = stream.tell()
        key_length = compact.read_from(stream)
        if key_length == 0:
            maps.append((fields, start, records))
            fields, records = {}, []
            continue
        key = stream.read(key_length)
        value = stream.read(compact.read_from(stream))
        if len(key) != key_length or key in fields:
            raise ValueError("truncated or duplicated field")
        fields[key] = value
        records.append((key, value, start, stream.tell()))
    if fields:
        raise ValueError("unterminated map")
    return maps


def splice_signatures(psbt, signatures: list) -> bytes:
    """
    The psbt's own bytes with one PSBT_IN_TAP_KEY_SIG added to each input map, just
    before its terminator. Every other byte, and the order they came in, are the
    request's own, so the response differs from it only by the signatures.

    The fields each signature was checked against must be the ones in these bytes,
    or they describe some other transaction and are not answered. Raises ValueError.
    """
    raw = getattr(psbt, _OWN_BYTES, None)
    if raw is None:
        raise ValueError("the psbt's own bytes were not kept")
    maps = _maps(raw)
    if len(maps) != 1 + len(psbt.inputs) + len(psbt.outputs):
        raise ValueError("the psbt's own bytes describe another transaction")

    signed, copied = bytearray(), 0
    for (fields, terminator, _records), inp, signature in zip(maps[1:], psbt.inputs, signatures):
        spend = {k: v for k, v in inp.unknown.items()
                 if k[0] in (IN_SP_SPEND_BIP32_DERIVATION, IN_SP_TWEAK)}
        if ({k: v for k, v in fields.items() if k[0] in (IN_SP_SPEND_BIP32_DERIVATION, IN_SP_TWEAK)} != spend
                or fields.get(b"\x01") != inp.witness_utxo.serialize()):
            raise ValueError("the psbt's own bytes describe another input")
        signed += raw[copied:terminator]
        signed += compact.to_bytes(len(IN_TAP_KEY_SIG)) + IN_TAP_KEY_SIG
        signed += compact.to_bytes(len(signature)) + signature
        copied = terminator
    signed += raw[copied:]
    return bytes(signed)


def spend_fields(inp):
    """
    An input's BIP-376 fields as (spend key, fingerprint, path, tweak): exactly one
    PSBT_IN_SP_SPEND_BIP32_DERIVATION (0x1f plus a 33-byte compressed key; a 4-byte
    fingerprint plus 4-byte little-endian path elements) and one PSBT_IN_SP_TWEAK
    (0x20 alone; 32 bytes). Raises ValueError for anything else.
    """
    derivations = [(k, v) for k, v in inp.unknown.items() if k[0] == IN_SP_SPEND_BIP32_DERIVATION]
    tweaks = [(k, v) for k, v in inp.unknown.items() if k[0] == IN_SP_TWEAK]
    if len(derivations) != 1 or len(tweaks) != 1:
        raise ValueError("needs one spend key and one tweak")
    (key, origin), (tweak_key, tweak) = derivations[0], tweaks[0]
    if len(key) != 34 or len(origin) < 4 or len(origin) % 4 or len(tweak_key) != 1 or len(tweak) != 32:
        raise ValueError("wrong field length")
    try:
        ec.PublicKey.parse(key[1:])
    except Exception as e:
        raise ValueError("invalid spend key") from e
    path = [int.from_bytes(origin[i:i + 4], "little") for i in range(4, len(origin), 4)]
    return key[1:], origin[:4], path, tweak


def master_fingerprint(seed, network: str) -> bytes:
    """The fingerprint a spend key of this seed's is filed under. ValueError if it has none."""
    return _master_root(seed, network).my_fingerprint


def spend_signing_key(seed, network: str, inp) -> ec.PrivateKey:
    """
    The key to the output this input spends, d = (b_spend + tweak) mod n, once it is
    proven this seed's: the path and the whole 33-byte spend key are this seed's, the
    prevout is P2TR, the tweak is in 1..n-1, d is not 0, and x(d*G) is the output key.
    Raises ValueError otherwise, since a wrong tweak would sign for a key we don't own.

    d is returned as is, even when d*G has odd Y: BIP-340 signing negates it then.
    """
    spend_key, fingerprint, path, tweak = spend_fields(inp)
    root = _master_root(seed, network)
    if fingerprint != root.my_fingerprint or path != [H + 352, H + COIN_TYPES[network], H + 0, H + 0, 0]:
        raise ValueError("not this seed's spend key path")
    b_spend = root.derive(path).key
    if b_spend.sec() != spend_key:
        raise ValueError("not this seed's spend key")
    utxo = inp.witness_utxo
    if utxo is None or utxo.script_pubkey.script_type() != "p2tr":
        raise ValueError("does not spend a Taproot output")
    t = int.from_bytes(tweak, "big")
    if not 0 < t < N:
        raise ValueError("tweak out of range")
    d = (int.from_bytes(b_spend.secret, "big") + t) % N
    if d == 0:
        raise ValueError("tweak cancels the spend key")
    key = ec.PrivateKey(d.to_bytes(32, "big"))
    if key.xonly() != utxo.script_pubkey.data[2:]:
        raise ValueError("tweak does not produce the output key")
    return key


def sign_spend_inputs(psbt, seed, network: str) -> int:
    """
    Signs every input, each a BIP-376 spend, with SIGHASH_DEFAULT, and adds each
    64-byte signature as PSBT_IN_TAP_KEY_SIG: the signer's whole part, since BIP-376
    leaves finalising to the coordinator. Nothing else in the psbt is touched.

    Every signature is made and checked against its output key first, and the
    response is built before any of them is written, so on any failure (ValueError)
    the psbt is unchanged. The response is kept on the psbt: see psbt_bytes.
    """
    signatures = []
    for i, inp in enumerate(psbt.inputs):
        key = spend_signing_key(seed, network, inp)
        msg = psbt.sighash(i, sighash=SIGHASH.DEFAULT)
        sig = key.schnorr_sign(msg)
        del key
        if not ec.PublicKey.from_xonly(inp.witness_utxo.script_pubkey.data[2:]).schnorr_verify(sig, msg):
            raise ValueError("input %d signature does not verify" % i)
        signatures.append(sig.serialize())
    signed = splice_signatures(psbt, signatures)
    for inp, sig in zip(psbt.inputs, signatures):
        inp.unknown[IN_TAP_KEY_SIG] = sig
    remember_bytes(psbt, signed)
    return len(signatures)


# ---- Sending to a Silent Payment address (BIP-375) -----------------------------------

def _point(sec: bytes) -> ec.PublicKey:
    """A compressed public key, as ec.PublicKey. ValueError if it is not one."""
    try:
        return ec.PublicKey.parse(sec)
    except Exception as e:
        raise ValueError("not a public key") from e


def _generator() -> ec.PublicKey:
    """secp256k1's G. BIP-374 takes the generator as an argument; this is the only one used."""
    return ec.PrivateKey((1).to_bytes(32, "big")).get_public_key()


def _lincomb(pairs) -> ec.PublicKey:
    """
    The sum of scalar*point over `pairs`, or None for the point at infinity.

    Every elliptic curve operation Silent Payments needs is one of these, so this is
    the only place a backend difference can show up: embit's ctypes bindings do the
    multiplication in libsecp256k1, and its pure-Python fallback (a device without
    the library) has no ec_pubkey_tweak_mul, so the curve arithmetic embit uses to
    implement its own point addition is used directly instead. See _lincomb_python.
    """
    terms = [(point, scalar % N) for point, scalar in pairs]
    terms = [(point, scalar) for point, scalar in terms if scalar]
    if not terms:
        return None
    if not hasattr(secp256k1, "ec_pubkey_tweak_mul"):
        return _lincomb_python(terms)
    points = []
    for point, scalar in terms:
        # ec_pubkey_parse returns the library's own 64-byte internal point, and
        # ec_pubkey_tweak_mul multiplies it in place, as embit's own code does.
        pub = secp256k1.ec_pubkey_parse(point.sec())
        secp256k1.ec_pubkey_tweak_mul(pub, scalar.to_bytes(32, "big"))
        points.append(pub)
    try:
        return ec.PublicKey(secp256k1.ec_pubkey_combine(*points))
    except Exception:
        # The only way a sum of valid points fails is that it is the point at infinity.
        return None


def _lincomb_python(terms) -> ec.PublicKey:
    """_lincomb on embit's pure-Python curve, which sums the whole combination at once."""
    points = []
    for point, scalar in terms:
        parsed = pykey.ECPubKey()
        parsed.set(point.sec())
        if not parsed.valid:
            raise ValueError("not a public key")
        points.append((parsed.p, scalar))
    total = pykey.SECP256K1.affine(pykey.SECP256K1.mul(points))
    if total is None:
        return None
    result = pykey.ECPubKey()
    result.p, result.valid, result.compressed = total, True, True
    return ec.PublicKey.parse(bytes(result.get_bytes()))


def _scalar(data: bytes) -> int:
    """A 32-byte hash as a scalar. ValueError if it is 0 or not below the group order."""
    value = int.from_bytes(data, "big")
    if not 0 < value < N:
        raise ValueError("not a valid scalar")
    return value


def _dleq_challenge(a_point, b_point, c_point, r1, r2, generator_point, message: bytes) -> int:
    parts = (a_point, b_point, c_point, generator_point, r1, r2)
    return int.from_bytes(
        hashes.tagged_hash("BIP0374/challenge", b"".join(p.sec() for p in parts) + message), "big"
    ) % N


def _dleq_nonce(secret: bytes, a_point, c_point, aux: bytes, message: bytes) -> bytes:
    tweaked = bytes(a ^ b for a, b in zip(secret, hashes.tagged_hash("BIP0374/aux", aux)))
    rand = hashes.tagged_hash("BIP0374/nonce", tweaked + a_point.sec() + c_point.sec() + message)
    return (int.from_bytes(rand, "big") % N).to_bytes(32, "big")


def dleq_prove(secret: bytes, b_point: ec.PublicKey, aux: bytes, message: bytes = b"",
               generator: ec.PublicKey = None) -> bytes:
    """
    BIP-374 GenerateProof: proof that C = secret*B and A = secret*G share one secret,
    as bytes(32, e) || bytes(32, s). `aux` must be fresh randomness for each proof.

    Raises ValueError for a secret out of range, a nonce of zero, or a proof that
    does not verify, so a proof is never handed out unchecked.
    """
    g = generator or _generator()
    a = int.from_bytes(secret, "big")
    if not 0 < a < N:
        raise ValueError("secret out of range")
    a_point, c_point = _lincomb([(g, a)]), _lincomb([(b_point, a)])
    if a_point is None or c_point is None:
        raise ValueError("statement is the point at infinity")
    k = int.from_bytes(_dleq_nonce(secret, a_point, c_point, aux, message), "big")
    if k == 0:
        raise ValueError("nonce is zero")
    r1, r2 = _lincomb([(g, k)]), _lincomb([(b_point, k)])
    if r1 is None or r2 is None:
        raise ValueError("nonce point is the point at infinity")
    e = _dleq_challenge(a_point, b_point, c_point, r1, r2, g, message)
    s = (k + e * a) % N
    proof = e.to_bytes(32, "big") + s.to_bytes(32, "big")
    if not dleq_verify(a_point, b_point, c_point, proof, message=message, generator=g):
        raise ValueError("proof does not verify")
    return proof


def dleq_verify(a_point: ec.PublicKey, b_point: ec.PublicKey, c_point: ec.PublicKey,
                proof: bytes, message: bytes = b"", generator: ec.PublicKey = None) -> bool:
    """
    BIP-374 VerifyProof: whether `proof` shows that A and C come from one secret.

    Returns False rather than raising, so a coordinator's proof that does not hold is
    a decision the caller makes (a refusal), not an exception path.
    """
    g = generator or _generator()
    if len(proof) != 64:
        return False
    e, s = int.from_bytes(proof[:32], "big"), int.from_bytes(proof[32:], "big")
    if e >= N or s >= N:
        return False
    r1 = _lincomb([(g, s), (a_point, N - e)])
    r2 = _lincomb([(b_point, s), (c_point, N - e)])
    if r1 is None or r2 is None:
        return False
    return e == _dleq_challenge(a_point, b_point, c_point, r1, r2, g, message)


def ecdh_share(secret: bytes, b_point: ec.PublicKey) -> ec.PublicKey:
    """C = secret*B_scan, the ECDH share BIP-375 publishes with a DLEQ proof."""
    share = _lincomb([(b_point, int.from_bytes(secret, "big"))])
    if share is None:
        raise ValueError("ECDH share is the point at infinity")
    return share


def even_y_secret(secret: bytes) -> bytes:
    """
    A Taproot input's key as BIP-352 uses it: negated when its point has odd Y.

    The receiver sums the x-only output keys and so assumes even Y for each of them;
    a sender that skipped this would compute a shared secret nobody can find.
    """
    if ec.PrivateKey(secret).get_public_key().sec()[0] == 0x02:
        return secret
    return (N - int.from_bytes(secret, "big")).to_bytes(32, "big")


def secret_sum(secrets: list) -> bytes:
    """a = a_1 + ... + a_n mod n. ValueError if the sum is zero, as BIP-352 requires."""
    total = sum(int.from_bytes(secret, "big") for secret in secrets) % N
    if total == 0:
        raise ValueError("the input keys sum to zero")
    return total.to_bytes(32, "big")


def input_hash(outpoints: list, a_point: ec.PublicKey) -> bytes:
    """
    BIP-352's input_hash, binding the payment to this exact set of inputs: the
    smallest outpoint of the whole transaction, serialized, and A = a*G.
    """
    if not outpoints:
        raise ValueError("no inputs to hash")
    digest = hashes.tagged_hash("BIP0352/Inputs", min(outpoints) + a_point.sec())
    _scalar(digest)
    return digest


def output_script(share: ec.PublicKey, spend_point: ec.PublicKey, hash_of_inputs: bytes,
                  k: int) -> bytes:
    """
    The P2TR script paying recipient k of a scan-key group: B_m + t_k*G, where
    t_k = hash_BIP0352/SharedSecret(ser(input_hash*C) || ser32(k)) and C is the ECDH
    share. Raises ValueError if any scalar is out of range, rather than paying a key
    the recipient cannot find.
    """
    shared = _lincomb([(share, _scalar(hash_of_inputs))])
    if shared is None:
        raise ValueError("shared secret is the point at infinity")
    tweak = hashes.tagged_hash("BIP0352/SharedSecret", shared.sec() + k.to_bytes(4, "big"))
    output = _lincomb([(_generator(), _scalar(tweak)), (spend_point, 1)])
    if output is None:
        raise ValueError("output key is the point at infinity")
    return b"\x51\x20" + output.xonly()


def code_order(codes: list) -> list:
    """
    The k of each output, from its (scan key, spend key) pair, per BIP-375: codes
    sharing a scan key are sorted lexicographically, and codes sharing both keys by
    output index. Output order alone is not the ordering.
    """
    groups = {}
    for index, (scan, spend) in enumerate(codes):
        groups.setdefault(scan, []).append((spend, index))
    order = {}
    for members in groups.values():
        if len(members) > K_MAX:
            raise ValueError("too many payments to one scan key")
        for k, (_, index) in enumerate(sorted(members)):
            order[index] = k
    return [order[index] for index in range(len(codes))]
