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

from embit import bech32, compact, ec
from embit.bip32 import HARDENED_INDEX as H
from embit.transaction import SIGHASH

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

    Only a spend, so that no other flow's export changes, and so a large psbt read
    from a card is not held twice for nothing.
    """
    if any(is_spend_input(inp) for inp in psbt.inputs):
        setattr(psbt, _OWN_BYTES, bytes(raw))


def has_own_bytes(psbt) -> bool:
    return getattr(psbt, _OWN_BYTES, None) is not None


def psbt_bytes(psbt) -> bytes:
    """The bytes this psbt arrived as (or was signed into), else embit's serialization."""
    return getattr(psbt, _OWN_BYTES, None) or psbt.serialize()


def _maps(raw: bytes) -> list:
    """Each key-value map of a serialized psbt, as (fields, offset of its terminator)."""
    stream = BytesIO(raw)
    if stream.read(5) != b"psbt\xff":
        raise ValueError("not a psbt")
    maps, fields = [], {}
    while stream.tell() < len(raw):
        key_length = compact.read_from(stream)
        if key_length == 0:
            maps.append((fields, stream.tell() - 1))
            fields = {}
            continue
        key = stream.read(key_length)
        value = stream.read(compact.read_from(stream))
        if len(key) != key_length or key in fields:
            raise ValueError("truncated or duplicated field")
        fields[key] = value
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
    for (fields, terminator), inp, signature in zip(maps[1:], psbt.inputs, signatures):
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
