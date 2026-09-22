"""
Silent Payments scan-key export.

The vectors come from four independent implementations, so a mistake shared with
any one of them still shows up:

* BIP-352's own receiving vectors (the unlabeled address of each distinct key pair
  across its 29 receiving cases);
* earthdiver's seed vectors in SeedSigner issue #769 (address and spscan key);
* Sparrow's drongo seed tests (testnet address);
* kiss-signer's (keys, addresses and the sp(...) scan export for abandon...about).
"""
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import tempfile
import textwrap
import time
from binascii import a2b_base64
from io import BytesIO
from unittest.mock import MagicMock

import pytest
import qrcode
from embit import bip32, bip39, compact, ec, script
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import SIGHASH

from base import BaseTest, FlowStep, FlowTest
from ui_driver import DeferredInput, UISession

from seedsigner.helpers import silent_payments
from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser, RejectCode
from seedsigner.models.seed import AezeedSeed, ElectrumSeed, Seed, Slip39Seed, XprvSeed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import psbt_views, scan_views, seed_views
from seedsigner.views.view import MainMenuView


MAINNET = SettingsConstants.MAINNET
TESTNET = SettingsConstants.TESTNET
REGTEST = SettingsConstants.REGTEST

ABANDON = ["abandon"] * 11 + ["about"]

# abandon...about, account 0, cross-checked against kiss-signer and Sparrow.
ABANDON_MAINNET_ADDRESS = "sp1qqfqnnv8czppwysafq3uwgwvsc638hc8rx3hscuddh0xa2yd746s7xqh6yy9ncjnqhqxazct0fzh98w7lpkm5fvlepqec2yy0sxlq4j6ccc3h6t0g"
ABANDON_MAINNET_EXPORT = "[73c5da0a/352h/0h/0h]spscan1q0rnl6lft0gkpg4nsn528qgdpytfdej40atdqgrxpqqsg8c5r8vys973ppv7y5c9cphgkzm6g4efmhhcdkazt87ggxwz3pruphc9vkkxxhtvyag"
ABANDON_TESTNET_ADDRESS = "tsp1qqdpels3srq45dlezqvk20t3dlueftry6p5thc7msjm0s6jm3g84jzq5rxzzunfck6d45va2jcqxk429agt3e4klf3vzmcgp3zqthryhhqgnz4k3n"


# BIP-352 send_and_receive_test_vectors.json: (scan priv, spend priv, unlabeled address)
BIP352_RECEIVING = [
    ("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c", "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
     "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"),
    ("060b751d7892149006ed7b98606955a29fe284a1e900070c0971f5fb93dbf422", "9902c3c56e84002a7cd410113a9ab21d142be7f53cf5200720bb01314c5eb920",
     "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn"),
    ("11b7a82e06ca2648d5fded2366478078ec4fc9dc1d8ff487518226f229d768fd", "b8f87388cbb41934c50daca018901b00070a5ff6cc25a7e9e716a9d5b9e4d664",
     "sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqauj52ymtc4xdkmx3tgyhrsemg2g3303xk2gtzfy8h8ejet8fz8jcw23zua"),
    ("0000000000000000000000000000000000000000000000000000000000000002", "0000000000000000000000000000000000000000000000000000000000000001",
     "sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s"),
    ("000000000000000000000000000000000000000000000000000000000000dead", "000000000000000000000000000000000000000000000000000000000000beef",
     "sp1qqtnvg7hxjck9ag24naytgd7pjwsmevwh95ydwht58w3uh7uw0ta7kq6xcdal4dazgg2txp472hdz4svms98328lqdflmpxppmc6ykamcrv9s7w9g"),
]

# SeedSigner issue #769 (earthdiver): (mnemonic, network, address, spscan key)
EARTHDIVER = [
    ("initial tilt corn easily leave weather strategy return topple gesture sad day", TESTNET,
     "tsp1qqfvn9pmvmz0ewpnp7w302lxqmnue2kgtpne2p38nuunun883sw36yq48ny7n2jl0nx9ljhmdnrgvpee6aufmg9wfvqfcr6c02at6r4u4xsegph7a",
     "tspscan1q09zrmaz09cdzs5jxm552qpv3f2gxd9vxhs0yady09jdd6aqt5e7s9fue8565hmue30u47mvc6rqwwwh0zw6ptjtqzwq7kr6h27sa09f5g6x977"),
    ("tongue vanish post gentle fever figure kangaroo select infant blur phrase relief", MAINNET,
     "sp1qq2c4jvrju33tmm9ll0560vm0rflfxkhd8zj74pka8s53dyaztzwlqqhrkuv0ut7wjv08kdq26t4twguxdcd9m35p6z4n784wyg3efwruevxty23x",
     "spscan1qnd95fpg2587jn73qg98pq8uk20y09v5c20u0e4kynsc4m2qmkrrs9cahrrlzln5nreangzkja2mj8pnwrfwudqws4vl3at3zyw2tslxtryq7pn"),
    ("index today witness obscure ugly curtain symbol pumpkin pelican child maple struggle arctic water tiny pizza harbor below violin eight tennis frost clown hood", TESTNET,
     "tsp1qqvdcq76j5kul4s6t52d07ssq8l96k49jur0kytua36k9qzj4m5xyxq5j2v4hc8njddv9xtnhly7hyv2agt28fypqn29q8mw3fjjlz00vvv824hd6",
     "tspscan1q0z4tkwaar4ww77qgesalgzw0c40q89zh7p7hmp3qn73yrdw9jpvs9yjn9d7puunttpfjuale84erzh2z636fqgy63gp7m52v5hcnmmrrlrxnur"),
    ("fold cotton pipe robust eagle rabbit coach average orient utility minor absurd fine claim artist rabbit kingdom original lobster cruise march city vibrant resemble", MAINNET,
     "sp1qq25f3laffnhpl69ytaxzz5gjnkrm2a2jr3mfz0ff6wuesg4j9e5lcqjj5qq7fy0t0wy9qvty7l7wk8vnmyxpxeq5ae0lmmzlgwnutg8945k2w7lh",
     "spscan1q79q4zljllyehszny72w5zfptzpxnp96esg0n2fwecgzd2v7fr6fsy54qq8jfr6mm3pgrze8hln43my7epsfkg98wtl77ch6r5lz6pedd2jcnxk"),
]

# Sparrow's drongo seed tests, testnet account 0: (mnemonic, address)
DRONGO = [
    ("life life life life life life life life life life life life",
     "tsp1qq0grgkzt7uwfst33pyge7k9mrkag0r9vrklc695n0pw7kwwc7qddqqley3n2a6z8q7vhkhzedtzj5kr86hv6fhh0zvu2j9tjrrxa4ye3acuv6f3q"),
    ("resist cube wrap sleep catalog shadow door scale stage rail script observe",
     "tsp1qqgksl44sjwjkedsmrfmf2xqsnyt2njtjp5plk2kzjlnd9el2n76awqe5j974lvkf2utv7nrg0eaug55z86n6n3v4e9alnftdzgqk6pqmm5dphvxn"),
]

# kiss-signer main/sp_spend_vectors.h and sim/test_sp.c, abandon...about
KISS_SPSCAN = {
    MAINNET: "sp([73c5da0a/352h/0h/0h]spscan1q0rnl6lft0gkpg4nsn528qgdpytfdej40atdqgrxpqqsg8c5r8vys973ppv7y5c9cphgkzm6g4efmhhcdkazt87ggxwz3pruphc9vkkxxhtvyag)",
    TESTNET: "sp([73c5da0a/352h/1h/0h]tspscan1q8pjcdy7qzlzxl44chw2tsanvzg7dtwhkqf3nsvzmdavls2ekl8qq9qesshy6w9knddr825kqp442302zuwddh6vtqk7zqvgszace9aczgnuqn3)",
}
KISS_KEYS = {
    # network: (scan pubkey, spend pubkey, address)
    MAINNET: ("024139b0f81042e243a90478e43990c6a27be0e3346f0c71adbbcdd511beaea1e3",
              "02fa210b3c4a60b80dd1616f48ae53bbdf0db744b3f9083385108f81be0acb58c6",
              ABANDON_MAINNET_ADDRESS),
    TESTNET: ("03439fc230182b46ff22032ca7ae2dff32958c9a0d177c7b7096df0d4b7141eb21",
              "02833085c9a716d36b467552c00d6aa8bd42e39adbe98b05bc203110177192f702",
              "tsp1qqdpels3srq45dlezqvk20t3dlueftry6p5thc7msjm0s6jm3g84jzq5rxzzunfck6d45va2jcqxk429agt3e4klf3vzmcgp3zqthryhhqgnz4k3n"),
}
KISS_MASTER_TPRV = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"

# SLIP-39's first official vector (tests/data/shamir_vectors.json), passphrase "TREZOR"
SLIP39_SHARE = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
SLIP39_XPRV = "xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchMDg6KME9HZtjfL7iThE9w5muQA4YPHKN1u5VM1w8D4pvnjxa2BmpGMfXr7hnRrRHZ93awZ"

# kiss-bdk's BIP-376 spend PSBTs (PSBTv2, testnet) for abandon...about. Their inputs
# carry only the Silent Payments spend fields (PSBT_IN_SP_SPEND_BIP32_DERIVATION and
# PSBT_IN_SP_TWEAK). 01-03 are signed; 04 carries a tweak that is not this seed's.
SP_SPEND_PSBTS = {
    "01-sp-spend-1in": (
        "cHNidP8B+wQCAAAAAQIEAgAAAAEDBNAHAAABBAEBAQUBAgEGAQAAAQ4gzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N"
        "zc0BDwQAAAAAARAE/f///wEBK6CGAQAAAAAAIlEggy6sZuy8/AB1immxfyXUgubE/0pVtKz8gxwVj5DleiUiHwKDMIXJpxbT"
        "a0Z1UsANaqi9QuOa2+mLBbwgMRAXcZL3AhhzxdoKYAEAgAEAAIAAAACAAAAAgAAAAAABICACAgICAgICAgICAgICAgICAgIC"
        "AgICAgICAgICAgICAgABAwhQwwAAAAAAAAEEFgAU0MSj7wnpl7bpnjl+UY/j5BoRjKEiAgLnqyU3tdSelwMJquBunknzbOHJ"
        "/rvUTsjg0cygtPnDGRhzxdoKVAAAgAEAAIAAAACAAAAAAAAAAAAAAQMIS8IAAAAAAAABBBYAFC80qhzwClOwVaKRoDp9RfCm"
        "mItSIgIDXUnszVTQCZ5DZ2J3x6bUYl1hHaiKXfSb+VF6d5Gnd6UYc8XaClQAAIABAACAAAAAgAEAAAAAAAAAAA=="
    ),
    "02-sp-spend-2in": (
        "cHNidP8B+wQCAAAAAQIEAgAAAAEDBNAHAAABBAECAQUBAgEGAQAAAQ4gzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N"
        "zc0BDwQBAAAAARAE/f///wEBK6CGAQAAAAAAIlEgvVeeFVtWreDEm9bGKsehICJNuvw++UUFWWPE4iAW0o8iHwKDMIXJpxbT"
        "a0Z1UsANaqi9QuOa2+mLBbwgMRAXcZL3AhhzxdoKYAEAgAEAAIAAAACAAAAAgAAAAAABICABAQEBAQEBAQEBAQEBAQEBAQEB"
        "AQEBAQEBAQEBAQEBAQABDiDNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzQEPBAAAAAABEAT9////AQEroIYBAAAA"
        "AAAiUSCDLqxm7Lz8AHWKabF/JdSC5sT/SlW0rPyDHBWPkOV6JSIfAoMwhcmnFtNrRnVSwA1qqL1C45rb6YsFvCAxEBdxkvcC"
        "GHPF2gpgAQCAAQAAgAAAAIAAAACAAAAAAAEgIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAAEDCNfBAAAAAAAA"
        "AQQWABQvNKoc8ApTsFWikaA6fUXwppiLUiICA11J7M1U0AmeQ2did8em1GJdYR2oil30m/lReneRp3elGHPF2gpUAACAAQAA"
        "gAAAAIABAAAAAAAAAAABAwjwSQIAAAAAAAEEFgAU0MSj7wnpl7bpnjl+UY/j5BoRjKEiAgLnqyU3tdSelwMJquBunknzbOHJ"
        "/rvUTsjg0cygtPnDGRhzxdoKVAAAgAEAAIAAAACAAAAAAAAAAAAA"
    ),
    "03-sp-spend-odd": (
        "cHNidP8B+wQCAAAAAQIEAgAAAAEDBNAHAAABBAEBAQUBAgEGAQAAAQ4gzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N"
        "zc0BDwQBAAAAARAE/f///wEBK6CGAQAAAAAAIlEgvVeeFVtWreDEm9bGKsehICJNuvw++UUFWWPE4iAW0o8iHwKDMIXJpxbT"
        "a0Z1UsANaqi9QuOa2+mLBbwgMRAXcZL3AhhzxdoKYAEAgAEAAIAAAACAAAAAgAAAAAABICABAQEBAQEBAQEBAQEBAQEBAQEB"
        "AQEBAQEBAQEBAQEBAQABAwhQwwAAAAAAAAEEFgAU0MSj7wnpl7bpnjl+UY/j5BoRjKEiAgLnqyU3tdSelwMJquBunknzbOHJ"
        "/rvUTsjg0cygtPnDGRhzxdoKVAAAgAEAAIAAAACAAAAAAAAAAAAAAQMIS8IAAAAAAAABBBYAFC80qhzwClOwVaKRoDp9RfCm"
        "mItSIgIDXUnszVTQCZ5DZ2J3x6bUYl1hHaiKXfSb+VF6d5Gnd6UYc8XaClQAAIABAACAAAAAgAEAAAAAAAAAAA=="
    ),
    "04-sp-spend-foreign-tweak": (
        "cHNidP8B+wQCAAAAAQIEAgAAAAEDBNAHAAABBAEBAQUBAgEGAQAAAQ4gzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N"
        "zc0BDwQAAAAAARAE/f///wEBK6CGAQAAAAAAIlEggy6sZuy8/AB1immxfyXUgubE/0pVtKz8gxwVj5DleiUiHwKDMIXJpxbT"
        "a0Z1UsANaqi9QuOa2+mLBbwgMRAXcZL3AhhzxdoKYAEAgAEAAIAAAACAAAAAgAAAAAABICB3d3d3d3d3d3d3d3d3d3d3d3d3"
        "d3d3d3d3d3d3d3d3dwABAwhQwwAAAAAAAAEEFgAU0MSj7wnpl7bpnjl+UY/j5BoRjKEiAgLnqyU3tdSelwMJquBunknzbOHJ"
        "/rvUTsjg0cygtPnDGRhzxdoKVAAAgAEAAIAAAACAAAAAAAAAAAAAAQMIS8IAAAAAAAABBBYAFC80qhzwClOwVaKRoDp9RfCm"
        "mItSIgIDXUnszVTQCZ5DZ2J3x6bUYl1hHaiKXfSb+VF6d5Gnd6UYc8XaClQAAIABAACAAAAAgAEAAAAAAAAAAA=="
    ),
}

ELECTRUM_MNEMONIC = "regular reject rare profit once math fringe chase until ketchup century escape"
AEZEED_MNEMONIC = (
    "absorb original enlist once climb erode kid thrive kitchen giant define tube "
    "orange leader harbor comfort olive fatal success suggest drink penalty chimney ritual"
)


def abandon_seed(passphrase: str = "") -> Seed:
    return Seed(list(ABANDON), passphrase=passphrase)


def child_xprv_seed() -> XprvSeed:
    """An xprv one level below the abandon...about master."""
    return XprvSeed(abandon_seed().get_root(MAINNET).derive("m/0h").to_base58())


def key_part(export: str) -> str:
    """The spscan1.../tspscan1... key, without its [origin]."""
    return export.split("]", 1)[1]



@pytest.mark.parametrize("scan_priv, spend_priv, address", BIP352_RECEIVING)
def test_bip352_receiving_vectors(scan_priv, spend_priv, address):
    scan_pub = ec.PrivateKey(bytes.fromhex(scan_priv)).sec()
    spend_pub = ec.PrivateKey(bytes.fromhex(spend_priv)).sec()
    assert silent_payments._bech32m("sp", scan_pub + spend_pub) == address


@pytest.mark.parametrize("mnemonic, network, address, spscan", EARTHDIVER)
def test_earthdiver_vectors(mnemonic, network, address, spscan):
    seed = Seed(mnemonic.split())
    assert silent_payments.address(seed, network) == address
    assert key_part(silent_payments.scan_key_export(seed, network)) == spscan


@pytest.mark.parametrize("mnemonic, address", DRONGO)
def test_drongo_vectors(mnemonic, address):
    assert silent_payments.address(Seed(mnemonic.split()), TESTNET) == address


@pytest.mark.parametrize("network", [MAINNET, TESTNET])
def test_kiss_signer_vectors(network):
    seed = abandon_seed()
    scan_pub, spend_pub, address = KISS_KEYS[network]

    scan, spend = silent_payments._keys(seed, network)
    assert scan.sec().hex() == scan_pub
    assert spend.sec().hex() == spend_pub
    assert silent_payments.address(seed, network) == address

    # Sparrow's SeedSigner import adds the sp(...) around the key expression itself.
    assert "sp(%s)" % silent_payments.scan_key_export(seed, network) == KISS_SPSCAN[network]


def test_kiss_signer_encodes_given_pubkeys():
    scan_pub = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    spend_pub = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
    assert silent_payments._bech32m("tsp", bytes.fromhex(scan_pub + spend_pub)) == (
        "tsp1qqfaysl7pn7mknpmmsapdd6sczx8ncnnjk84gcm0xq2n66jjpm0sxsqmpuxc7nhj7gt9jqplhef2tncx40mgnjw8664kn7x09w5f63l8q8ymd0lna"
    )


def test_abandon_mainnet_export_and_address():
    seed = abandon_seed()
    assert silent_payments.scan_key_export(seed, MAINNET) == ABANDON_MAINNET_EXPORT
    assert silent_payments.address(seed, MAINNET) == ABANDON_MAINNET_ADDRESS
    assert len(ABANDON_MAINNET_EXPORT) == 139
    assert len(ABANDON_MAINNET_ADDRESS) == 116


@pytest.mark.parametrize("network, path, origin", [
    (MAINNET, "m/352'/0'/0'", "/352h/0h/0h]spscan1q"),
    (TESTNET, "m/352'/1'/0'", "/352h/1h/0h]tspscan1q"),
])
def test_export_origin_matches_the_seed_options_fingerprint(network, path, origin):
    seed = abandon_seed("TREZOR")
    assert silent_payments.derivation_path(network) == path
    assert silent_payments.scan_key_export(seed, network).startswith("[" + seed.get_fingerprint(network) + origin)


def test_bip39_passphrase_changes_fingerprint_and_keys():
    plain, protected = abandon_seed(), abandon_seed("TREZOR")
    assert protected.get_fingerprint(MAINNET) != plain.get_fingerprint(MAINNET)
    assert silent_payments.address(protected, MAINNET) != silent_payments.address(plain, MAINNET)

    # The same keys as the passphrase seed's own master xprv gives.
    xprv = XprvSeed(protected.get_root(MAINNET).to_base58())
    assert silent_payments.address(protected, MAINNET) == silent_payments.address(xprv, MAINNET)
    assert silent_payments.scan_key_export(protected, MAINNET) == silent_payments.scan_key_export(xprv, MAINNET)


@pytest.mark.parametrize("network", [MAINNET, TESTNET])
def test_slip39_matches_its_official_xprv(network, monkeypatch):
    # Slip39Seed shows a loading screen while it combines the shares.
    monkeypatch.setattr("seedsigner.gui.screens.screen.LoadingScreenThread", MagicMock())
    slip39 = Slip39Seed(mnemonics=[SLIP39_SHARE], slip39_passphrase="TREZOR")
    xprv = XprvSeed(SLIP39_XPRV)
    assert silent_payments.is_supported(slip39, network)
    assert silent_payments.address(slip39, network) == silent_payments.address(xprv, network)
    assert silent_payments.scan_key_export(slip39, network) == silent_payments.scan_key_export(xprv, network)


@pytest.mark.parametrize("network", [MAINNET, TESTNET])
def test_master_xprv_matches_its_bip39_seed(network):
    # A tprv, on mainnet too: the version bytes don't change the keys.
    xprv = XprvSeed(KISS_MASTER_TPRV)
    assert silent_payments.is_supported(xprv, network)
    assert silent_payments.address(xprv, network) == silent_payments.address(abandon_seed(), network)
    assert silent_payments.scan_key_export(xprv, network) == silent_payments.scan_key_export(abandon_seed(), network)


@pytest.mark.parametrize("seed_factory, network", [
    (abandon_seed, REGTEST),
    (lambda: ElectrumSeed(ELECTRUM_MNEMONIC.split()), MAINNET),
    (lambda: AezeedSeed(mnemonic=AEZEED_MNEMONIC.split()), MAINNET),
    (child_xprv_seed, MAINNET),
    (child_xprv_seed, TESTNET),
], ids=["regtest", "electrum", "aezeed", "child-xprv-mainnet", "child-xprv-testnet"])
def test_helper_refuses_unsupported_seeds_and_networks(seed_factory, network):
    seed = seed_factory()
    assert not silent_payments.is_supported(seed, network)
    with pytest.raises(ValueError):
        silent_payments.address(seed, network)
    with pytest.raises(ValueError):
        silent_payments.scan_key_export(seed, network)



class PressOnceTheQRIsDrawn(DeferredInput):
    """Leave the QR screen, but only after its display thread has drawn a frame."""
    frames = None

    def _next_key(self, screen, watched_keys):
        from seedsigner.hardware.buttons import HardwareButtonsConstants
        if getattr(self, "pressed", False):
            return None
        # frames[0] is the blank canvas display() shows before the thread starts.
        deadline = time.time() + 10
        while len(self.frames) < 2 and time.time() < deadline:
            time.sleep(0.01)
        self.pressed = True
        return HardwareButtonsConstants.KEY_PRESS



class TestScanKeyQR(BaseTest):
    def test_real_qr_screen_draws_it_in_memory(self, monkeypatch):
        """
        The scan key never reaches a file: the real QRDisplayScreen draws its QR while
        every temp file and subprocess fails the test. (The other encoders go through
        QR.qrimage_io(), which writes the data to a temp file for the qrencode binary.)
        """
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import InMemoryStaticQrEncoder

        # No brightness tip over the bottom rows, so every module can be checked.
        self.settings.set_value(SettingsConstants.SETTING__QR_BRIGHTNESS_TIPS, SettingsConstants.OPTION__DISABLED)
        export = silent_payments.scan_key_export(abandon_seed(), MAINNET)

        forbidden = []
        def refuse(name):
            def refused(*args, **kwargs):
                # Raised on the display thread, where it would go unseen: record it too.
                forbidden.append(name)
                raise AssertionError(name + " used while drawing the scan key")
            return refused
        for name in ("NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile", "mkstemp", "mkdtemp"):
            monkeypatch.setattr(tempfile, name, refuse("tempfile." + name))
        monkeypatch.setattr(subprocess, "Popen", refuse("subprocess.Popen"))

        press = PressOnceTheQRIsDrawn()
        with UISession(script=[press]) as session:
            press.frames = session.renderer.frames
            screen = QRDisplayScreen(qr_encoder=InMemoryStaticQrEncoder(data=export))
            screen.display()
        monkeypatch.undo()

        assert forbidden == []
        assert key_part(export) not in repr(screen)
        assert len(session.renderer.frames) >= 2

        # The frame on screen is exactly this export's QR: version 7, error correction L.
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=0)
        qr.add_data(export)
        qr.make(fit=True)
        assert qr.version == 7
        matrix = qr.get_matrix()
        frame = session.renderer.frames[-1].convert("L")
        module = frame.width / (len(matrix) + 2 * 2)  # QRDisplayScreen draws a 2-module border
        for row, modules in enumerate(matrix):
            for col, dark in enumerate(modules):
                pixel = frame.getpixel((int((col + 2.5) * module), int((row + 2.5) * module)))
                assert (pixel == 0) == dark, (row, col)



class TestScanKeyStaysInTheQRView(FlowTest):
    def test_scan_key_reaches_no_log_destination_or_back_stack(self, caplog, monkeypatch):
        from seedsigner.models import encode_qr

        caplog.set_level(logging.DEBUG)
        self.settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS, SettingsConstants.OPTION__ENABLED)
        seed = abandon_seed()
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(ABANDON)))
        secrets = [
            ABANDON_MAINNET_EXPORT,
            key_part(ABANDON_MAINNET_EXPORT),
            root.derive("m/352h/0h/0h/1h/0").key.secret.hex(),
        ]

        drawn = []
        class RecordingEncoder(encode_qr.InMemoryStaticQrEncoder):
            def __post_init__(self):
                super().__post_init__()
                drawn.append(self.data)
        monkeypatch.setattr(encode_qr, "InMemoryStaticQrEncoder", RecordingEncoder)

        seen = []
        def record(view):
            """What this View was given, and every Destination on the back stack."""
            seen.append(repr(vars(view)))
            seen.append(repr([(d.View_cls.__name__, d.view_args) for d in view.controller.back_stack]))

        qr_views = []
        self.run_sequence([
            FlowStep(seed_views.SeedOptionsView, before_run=record, button_data_selection=seed_views.SeedOptionsView.SILENT_PAYMENTS),
            FlowStep(seed_views.SeedSilentPaymentsNoticeView, before_run=record, screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsMenuView, before_run=record, button_data_selection=seed_views.SeedSilentPaymentsMenuView.EXPORT_SCAN_KEY),
            FlowStep(seed_views.SeedSilentPaymentsWarningView, before_run=record, screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsDetailsView, before_run=record, screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsScanKeyQRView, before_run=qr_views.append),
            FlowStep(seed_views.SeedSilentPaymentsNextStepsView, before_run=record, screen_return_value=0),
            FlowStep(seed_views.SeedOptionsView),
        ], initial_destination_view_args=dict(seed=seed))
        seen.append(repr([(d.View_cls.__name__, d.view_args) for d in self.controller.back_stack]))
        # The QR View lets go of its Screen, and with it the encoder, once the QR closes.
        assert qr_views[0].screen is None
        seen.append(repr(vars(qr_views[0])))

        assert drawn == [ABANDON_MAINNET_EXPORT]
        logs = [r.getMessage() for r in caplog.records]
        assert any("SeedSilentPaymentsScanKeyQRView" in line for line in logs)
        for secret in secrets:
            assert not [line for line in logs if secret in line]
            assert not [entry for entry in seen if secret in entry]



class TestScanKeyQRBlocksTheScreensaver(FlowTest):
    def test_screensaver_cannot_start_on_the_scan_key_qr(self):
        """The screensaver keeps a copy of the last screen, so it must never copy this one."""
        self.settings.set_value(SettingsConstants.SETTING__SILENT_PAYMENTS, SettingsConstants.OPTION__ENABLED)
        self.run_sequence([
            FlowStep(seed_views.SeedSilentPaymentsDetailsView, screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsScanKeyQRView),
        ], initial_destination_view_args=dict(seed=abandon_seed()))

        assert self.controller.is_screensaver_start_allowed is False



class TestAddressRoute(FlowTest):
    def _capture_screen(self, captured):
        """A before_run hook that records the kwargs the View hands its Screen."""
        def hook(view):
            mocked = view.run_screen
            def run_screen(screen_cls, **kwargs):
                captured.append((screen_cls, kwargs))
                return mocked(screen_cls, **kwargs)
            view.run_screen = run_screen
        return hook

    def test_share_check_is_always_shown_and_focuses_export_first(self):
        # The share check is about losing payments, not privacy, so the privacy-warnings
        # setting doesn't skip it. Its first button, the default focus, is the export.
        self.settings.set_value(SettingsConstants.SETTING__PRIVACY_WARNINGS, SettingsConstants.OPTION__DISABLED)
        captured = []
        self.run_sequence([
            FlowStep(seed_views.SeedSilentPaymentsMenuView, button_data_selection=seed_views.SeedSilentPaymentsMenuView.SHOW_ADDRESS),
            FlowStep(seed_views.SeedSilentPaymentsShareCheckView, before_run=self._capture_screen(captured), screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsWarningView),
        ], initial_destination_view_args=dict(seed=abandon_seed()))
        _, kwargs = captured[0]
        assert kwargs["button_data"][0] == seed_views.SeedSilentPaymentsShareCheckView.EXPORT_FIRST
        assert kwargs["text"] == "Share only after Sparrow has the scan key and a birth date before your first payment."

    @pytest.mark.parametrize("network, display, address", [
        (SettingsConstants.MAINNET, "Mainnet", ABANDON_MAINNET_ADDRESS),
        (SettingsConstants.TESTNET, "Testnet", ABANDON_TESTNET_ADDRESS),
    ])
    def test_address_details_show_network_and_address(self, network, display, address):
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, network)
        captured = []
        self.run_sequence([
            FlowStep(seed_views.SeedSilentPaymentsAddressView, before_run=self._capture_screen(captured), screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsAddressQRView),
        ], initial_destination_view_args=dict(seed=abandon_seed()))
        _, kwargs = captured[0]
        assert kwargs["network"] == display
        assert kwargs["address"] == address
        assert kwargs["fingerprint"] == "73c5da0a"

    def test_address_route_never_exports_the_scan_key(self, caplog, monkeypatch):
        """
        Building the address derives the scan key inside the helper, which returns only
        the address. Nothing on this route asks for the export, and neither the key nor
        the export reaches a log line, a view's args or the back stack.
        """
        from seedsigner.models import encode_qr

        caplog.set_level(logging.DEBUG)
        def no_scan_key(*args, **kwargs):
            raise AssertionError("the address route built the scan-key export")
        monkeypatch.setattr(silent_payments, "scan_key_export", no_scan_key)

        drawn = []
        class RecordingEncoder(encode_qr.GenericStaticQrEncoder):
            def __post_init__(self):
                super().__post_init__()
                drawn.append(self.data)
        monkeypatch.setattr(encode_qr, "GenericStaticQrEncoder", RecordingEncoder)

        seen = []
        def record(view):
            seen.append(repr(vars(view)))
            seen.append(repr([(d.View_cls.__name__, d.view_args) for d in view.controller.back_stack]))

        self.run_sequence([
            FlowStep(seed_views.SeedSilentPaymentsMenuView, before_run=record, button_data_selection=seed_views.SeedSilentPaymentsMenuView.SHOW_ADDRESS),
            FlowStep(seed_views.SeedSilentPaymentsShareCheckView, before_run=record, button_data_selection=seed_views.SeedSilentPaymentsShareCheckView.SHOW_ADDRESS),
            FlowStep(seed_views.SeedSilentPaymentsAddressView, before_run=record, screen_return_value=0),
            FlowStep(seed_views.SeedSilentPaymentsAddressQRView, before_run=record),
            FlowStep(seed_views.SeedSilentPaymentsMenuView),
        ], initial_destination_view_args=dict(seed=abandon_seed()))

        assert drawn == [ABANDON_MAINNET_ADDRESS]
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(ABANDON)))
        secrets = [ABANDON_MAINNET_EXPORT, key_part(ABANDON_MAINNET_EXPORT), root.derive("m/352h/0h/0h/1h/0").key.secret.hex()]
        logs = [r.getMessage() for r in caplog.records]
        for secret in secrets:
            assert not [line for line in logs if secret in line]
            assert not [entry for entry in seen if secret in entry]



# ---- BIP-376: spending a received Silent Payment ------------------------------------

SECP_P = 2**256 - 2**32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % SECP_P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], SECP_P - 2, SECP_P) % SECP_P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], SECP_P - 2, SECP_P) % SECP_P
    x = (lam * lam - p[0] - q[0]) % SECP_P
    return x, (lam * (p[0] - x) - p[1]) % SECP_P


def _point_mul(point, k):
    result = None
    while k:
        if k & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        k >>= 1
    return result


def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def bip340_verify(xonly: bytes, msg: bytes, sig: bytes) -> bool:
    """BIP-340's verification algorithm, written out here so the check owes nothing to embit."""
    x = int.from_bytes(xonly, "big")
    y_sq = (pow(x, 3, SECP_P) + 7) % SECP_P
    y = pow(y_sq, (SECP_P + 1) // 4, SECP_P)
    if x >= SECP_P or y * y % SECP_P != y_sq or len(sig) != 64:
        return False
    pub = (x, y if y % 2 == 0 else SECP_P - y)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= SECP_P or s >= SECP_N:
        return False
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", sig[:32] + xonly + msg), "big") % SECP_N
    point = _point_add(_point_mul(SECP_G, s), _point_mul(pub, SECP_N - e))
    return point is not None and point[1] % 2 == 0 and point[0] == r


def xonly_of(d: int) -> bytes:
    return _point_mul(SECP_G, d)[0].to_bytes(32, "big")


def has_odd_y(d: int) -> bool:
    return _point_mul(SECP_G, d)[1] % 2 == 1


# kiss-signer main/sp_spend_vectors.h: (psbt, tweak byte, output key, BIP-341 sighash)
KISS_SPEND_VECTORS = {
    "even": (
        "cHNidP8BAgQCAAAAAQQBAQEFAQEBBgEAAfsEAgAAAAABASughgEAAAAAACJRIIMurGbsvPwAdYppsX8l1ILmxP9KVbSs/IMcFY+Q5XolAQ4gzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0BDwQAAAAAARAE/v///yIfAoMwhcmnFtNrRnVSwA1qqL1C45rb6YsFvCAxEBdxkvcCGHPF2gpgAQCAAQAAgAAAAIAAAACAAAAAAAEgIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAAEDCBhzAQAAAAAAAQQWABQvNKoc8ApTsFWikaA6fUXwppiLUgA=",
        0x02, "832eac66ecbcfc00758a69b17f25d482e6c4ff4a55b4acfc831c158f90e57a25",
        "116f2e2f84c78c68b33d4ce1bf82c8461f6e7b54136b89623ac2a759d48a05ff",
    ),
    "odd": (
        "cHNidP8BAgQCAAAAAQQBAQEFAQEBBgEAAfsEAgAAAAABASughgEAAAAAACJRIL1XnhVbVq3gxJvWxirHoSAiTbr8PvlFBVljxOIgFtKPAQ4gzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0BDwQAAAAAARAE/v///yIfAoMwhcmnFtNrRnVSwA1qqL1C45rb6YsFvCAxEBdxkvcCGHPF2gpgAQCAAQAAgAAAAIAAAACAAAAAAAEgIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEDCBhzAQAAAAAAAQQWABQvNKoc8ApTsFWikaA6fUXwppiLUgA=",
        0x01, "bd579e155b56ade0c49bd6c62ac7a120224dbafc3ef945055963c4e22016d28f",
        "4b91a4474619202c813696358e676a913e831587c71b2abdf6b31c446023aea9",
    ),
}
KISS_SPEND_FOREIGN = "cHNidP8BAgQCAAAAAQQBAQEFAQEBBgEAAfsEAgAAAAABASughgEAAAAAACJRIIMurGbsvPwAdYppsX8l1ILmxP9KVbSs/IMcFY+Q5XolAQ4gzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0BDwQAAAAAARAE/v///yIfAoMwhcmnFtNrRnVSwA1qqL1C45rb6YsFvCAxEBdxkvcCGHPF2gpgAQCAAQAAgAAAAIAAAACAAAAAAAEgIHd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3AAEDCBhzAQAAAAAAAQQWABQvNKoc8ApTsFWikaA6fUXwppiLUgA="

SIGNED_FIXTURES = ["01-sp-spend-1in", "02-sp-spend-2in", "03-sp-spend-odd"]
SPEND_KEY_TYPE = 0x1F


def parse_kept(raw: bytes) -> PSBT:
    """Parse a psbt the way a scan does, keeping the bytes it came in as."""
    p = PSBT.parse(raw)
    silent_payments.remember_bytes(p, raw)
    return p


def sp_psbt(name: str) -> PSBT:
    return parse_kept(a2b_base64(SP_SPEND_PSBTS[name]))


def reparse(p: PSBT) -> PSBT:
    """Round-trip through bytes, so embit files each field where a scanned psbt would have it."""
    return parse_kept(p.serialize())


def b_spend() -> int:
    """The abandon...about testnet spend private key, m/352'/1'/0'/0'/0."""
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(ABANDON)))
    return int.from_bytes(root.derive("m/352h/1h/0h/0h/0").key.secret, "big")


def spend_key_field(inp):
    return next(k for k in inp.unknown if k[0] == SPEND_KEY_TYPE)


def set_spend(inp, tweak: int, d: int = None):
    """Give an input tweak `tweak`, and a P2TR prevout paying x(d*G) (by default, b_spend + tweak)."""
    inp.unknown[b"\x20"] = tweak.to_bytes(32, "big")
    d = (b_spend() + tweak) % SECP_N if d is None else d
    inp.witness_utxo.script_pubkey = script.Script(b"\x51\x20" + xonly_of(d))


def raw_maps(data: bytes) -> list[dict]:
    """Every key-value map of a serialized psbt, in order, read straight from the bytes."""
    stream = BytesIO(data[5:])
    maps, current = [], {}
    while stream.tell() < len(data) - 5:
        key = stream.read(compact.read_from(stream))
        if not key:
            maps.append(current)
            current = {}
            continue
        assert key not in current
        current[key] = stream.read(compact.read_from(stream))
    return maps


def strip_tap_key_sigs(data: bytes) -> bytes:
    """Every byte of a psbt except its PSBT_IN_TAP_KEY_SIG records, found by walking the maps."""
    stream = BytesIO(data)
    out = bytearray(stream.read(5))
    while stream.tell() < len(data):
        start = stream.tell()
        key_len = compact.read_from(stream)
        if key_len:
            key = stream.read(key_len)
            stream.read(compact.read_from(stream))
            if key == b"\x13":
                continue
        out += data[start:stream.tell()]
    return bytes(out)


def assert_only_signatures_added(before: bytes, after: bytes, num_inputs: int):
    """`after` is `before` byte for byte, with one 64-byte 0x13 added to each input map."""
    assert after != before
    assert strip_tap_key_sigs(after) == before
    signatures = [m.get(b"\x13") for m in raw_maps(after)[1:1 + num_inputs]]
    assert all(sig is not None and len(sig) == 64 for sig in signatures)
    assert all(b"\x13" not in m for m in raw_maps(after)[1 + num_inputs:])


def assert_signatures_verify(p: PSBT):
    for i, inp in enumerate(p.inputs):
        sig = inp.unknown[b"\x13"]
        assert len(sig) == 64
        msg = p.sighash(i, sighash=SIGHASH.DEFAULT)
        assert bip340_verify(inp.witness_utxo.script_pubkey.data[2:], msg, sig)


def parse_testnet(p: PSBT, seed=None) -> PSBTParser:
    return PSBTParser(p, seed=seed or abandon_seed(), network=TESTNET)


def assert_refused(p: PSBT, code: str, seed=None, match: str = None):
    with pytest.raises(InvalidPSBTError, match=match) as e:
        parse_testnet(reparse(p), seed)
    assert e.value.code == code
    return e.value


class TestSpendSigning:
    @pytest.mark.parametrize("name", SIGNED_FIXTURES)
    def test_kiss_bdk_fixtures_are_signed_losslessly(self, name, monkeypatch):
        monkeypatch.setattr(PSBT, "sign_with", MagicMock(side_effect=AssertionError("sign_with()")))
        raw = a2b_base64(SP_SPEND_PSBTS[name])
        p = parse_kept(raw)
        parser = parse_testnet(p)
        assert parser.silent_payment_inputs == [True] * len(p.inputs)
        assert PSBTParser.sig_count(p) == 0

        assert silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET) == len(p.inputs)
        assert PSBTParser.sig_count(p) == len(p.inputs)
        assert_signatures_verify(p)
        assert_only_signatures_added(raw, silent_payments.psbt_bytes(p), len(p.inputs))
        assert p.version == 2

    def test_foreign_tweak_refused_before_signing(self):
        p = sp_psbt("04-sp-spend-foreign-tweak")
        assert_refused(p, RejectCode.FOREIGN_SILENT_PAYMENT)
        before = p.serialize()
        with pytest.raises(ValueError):
            silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        assert p.serialize() == before

    @pytest.mark.parametrize("name", sorted(KISS_SPEND_VECTORS))
    def test_kiss_signer_vectors(self, name):
        b64, tweak_byte, outkey, sighash = KISS_SPEND_VECTORS[name]
        p = parse_kept(a2b_base64(b64))
        parse_testnet(p)
        assert p.sighash(0, sighash=SIGHASH.DEFAULT).hex() == sighash
        key = silent_payments.spend_signing_key(abandon_seed(), TESTNET, p.inputs[0])
        d = (b_spend() + int.from_bytes(bytes([tweak_byte]) * 32, "big")) % SECP_N
        # The key is d itself, never negated by the helper, whichever Y parity d*G has.
        assert key.secret == d.to_bytes(32, "big")
        assert has_odd_y(d) == (name == "odd")
        assert key.xonly().hex() == outkey
        silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        assert bip340_verify(bytes.fromhex(outkey), bytes.fromhex(sighash), p.inputs[0].unknown[b"\x13"])

    def test_kiss_signer_foreign_vector_refused(self):
        assert_refused(parse_kept(a2b_base64(KISS_SPEND_FOREIGN)), RejectCode.FOREIGN_SILENT_PAYMENT)

    @pytest.mark.parametrize("backend", ["ctypes", "python"])
    def test_both_secp256k1_backends_sign_both_parities(self, backend):
        """
        embit picks libsecp256k1 through ctypes when it loads and falls back to its
        pure-Python maths otherwise (embit/util/secp256k1.py). Neither may need the
        helper to negate d for an odd-Y output key, so each signs every fixture in a
        fresh interpreter, and each signature is checked here.
        """
        code = textwrap.dedent("""
            import json, sys
            if sys.argv[1] == "python":
                sys.modules["embit.util.ctypes_secp256k1"] = None  # makes the import fail
            from binascii import a2b_base64, b2a_base64
            from embit.psbt import PSBT
            from embit.util import secp256k1
            from seedsigner.helpers import silent_payments
            from seedsigner.models.seed import Seed
            from seedsigner.models.settings_definition import SettingsConstants
            seed = Seed(["abandon"] * 11 + ["about"])
            out = {"backend": secp256k1.schnorrsig_sign.__module__, "signed": {}}
            for name, b64 in json.loads(sys.stdin.read()).items():
                raw = a2b_base64(b64)
                p = PSBT.parse(raw)
                silent_payments.remember_bytes(p, raw)
                silent_payments.sign_spend_inputs(p, seed, SettingsConstants.TESTNET)
                out["signed"][name] = b2a_base64(silent_payments.psbt_bytes(p)).decode().strip()
            print(json.dumps(out))
        """)
        inputs = {name: SP_SPEND_PSBTS[name] for name in SIGNED_FIXTURES}
        inputs.update({name: KISS_SPEND_VECTORS[name][0] for name in KISS_SPEND_VECTORS})
        result = subprocess.run(
            [sys.executable, "-c", code, backend], input=json.dumps(inputs),
            capture_output=True, text=True, check=True, timeout=300,
            env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")},
        )
        out = json.loads(result.stdout)
        expected = {"ctypes": "embit.util.ctypes_secp256k1", "python": "embit.util.py_secp256k1"}
        assert out["backend"] == expected[backend]
        parities = set()
        for name, b64 in out["signed"].items():
            signed = a2b_base64(b64)
            assert_only_signatures_added(a2b_base64(inputs[name]), signed, len(PSBT.parse(signed).inputs))
            p = PSBT.parse(signed)
            assert_signatures_verify(p)
            for inp in p.inputs:
                d = (b_spend() + int.from_bytes(inp.unknown[b"\x20"], "big")) % SECP_N
                parities.add(has_odd_y(d))
        assert parities == {True, False}

    def test_random_non_symmetric_tweaks(self):
        rng = random.Random(376)
        parities = set()
        while parities != {True, False}:
            p = sp_psbt("02-sp-spend-2in")
            for inp in p.inputs:
                tweak = rng.randrange(1, SECP_N)
                set_spend(inp, tweak)
                parities.add(has_odd_y((b_spend() + tweak) % SECP_N))
            p = reparse(p)
            parse_testnet(p)
            silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
            assert_signatures_verify(p)

    def test_tweak_n_minus_one_is_signed(self):
        p = sp_psbt("01-sp-spend-1in")
        set_spend(p.inputs[0], SECP_N - 1)
        p = reparse(p)
        parse_testnet(p)
        silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        assert_signatures_verify(p)

    @pytest.mark.parametrize("case", ["t=0", "t=n", "t=2^256-1", "b_spend+t=0", "off-by-one"])
    def test_scalar_boundaries_refused(self, case):
        b = b_spend()
        p = sp_psbt("01-sp-spend-1in")
        inp = p.inputs[0]
        if case == "t=0":
            set_spend(inp, 0)          # the output key is the bare spend key
        elif case == "t=n":
            set_spend(inp, SECP_N)     # the same key again, reached by t = n
        elif case == "t=2^256-1":
            set_spend(inp, 2**256 - 1)
        elif case == "b_spend+t=0":
            set_spend(inp, SECP_N - b, d=b)
        else:
            set_spend(inp, 0x0202020202020202020202020202020202020202020202020202020202020203, d=b + 0x0202020202020202020202020202020202020202020202020202020202020202)
        assert_refused(p, RejectCode.FOREIGN_SILENT_PAYMENT)
        with pytest.raises(ValueError):
            silent_payments.sign_spend_inputs(reparse(p), abandon_seed(), TESTNET)

    def test_late_failure_leaves_psbt_unchanged(self, monkeypatch):
        """A signature that fails its check on the second input: nothing is written to either."""
        p = sp_psbt("02-sp-spend-2in")
        parse_testnet(p)
        before = p.serialize()
        real_sign = ec.PrivateKey.schnorr_sign
        calls = []
        def sign(key, msg):
            calls.append(msg)
            sig = real_sign(key, msg)
            return sig if len(calls) == 1 else real_sign(key, bytes(32))
        monkeypatch.setattr(ec.PrivateKey, "schnorr_sign", sign)
        with pytest.raises(ValueError):
            silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        assert len(calls) == 2
        assert p.serialize() == before
        assert all(b"\x13" not in inp.unknown for inp in p.inputs)

    def test_master_xprv_signs(self):
        p = sp_psbt("01-sp-spend-1in")
        xprv = XprvSeed(KISS_MASTER_TPRV)
        parse_testnet(p, xprv)
        silent_payments.sign_spend_inputs(p, xprv, TESTNET)
        assert_signatures_verify(p)


class TestSpendRefusals:
    @pytest.mark.parametrize("sighash", [0x01, 0x02, 0x03, 0x80, 0x81, 0x82, 0x83])
    def test_only_sighash_default(self, sighash):
        p = sp_psbt("01-sp-spend-1in")
        p.inputs[0].sighash_type = sighash
        assert_refused(p, RejectCode.UNSUPPORTED_SIGHASH)

    def test_explicit_sighash_default_is_signed(self):
        p = sp_psbt("01-sp-spend-1in")
        p.inputs[0].sighash_type = 0x00
        p = reparse(p)
        parse_testnet(p)
        silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        assert_signatures_verify(p)

    @pytest.mark.parametrize("scope, key", [
        ("global", b"\x07" + bytes.fromhex(KISS_KEYS[TESTNET][0])),
        ("global", b"\x08" + bytes.fromhex(KISS_KEYS[TESTNET][0])),
        ("input", b"\x1d" + bytes.fromhex(KISS_KEYS[TESTNET][0])),
        ("input", b"\x1e" + bytes.fromhex(KISS_KEYS[TESTNET][0])),
        ("output", b"\x09"),
        ("output", b"\x0a"),
    ])
    def test_send_fields_refused_before_the_output_check(self, scope, key):
        """BIP-375 fields are refused first, even on a psbt whose output has no script."""
        p = sp_psbt("01-sp-spend-1in")
        p.outputs[0].script_pubkey = None
        {"global": p, "input": p.inputs[0], "output": p.outputs[1]}[scope].unknown[key] = b"\x01" * 33
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="Sending to Silent Payment")

    def test_send_fields_refused_on_ordinary_psbt(self):
        p = parse_kept(a2b_base64(KISS_SPEND_VECTORS["even"][0]))
        for key in list(p.inputs[0].unknown):
            del p.inputs[0].unknown[key]
        p.outputs[0].unknown[b"\x09"] = b"\x01" * 66
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="Sending to Silent Payment")

    def test_v0_refused(self):
        p = sp_psbt("01-sp-spend-1in")
        p.version = None
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="v2")

    def test_mixed_inputs_refused(self):
        p = sp_psbt("02-sp-spend-2in")
        p.inputs[1].unknown.clear()
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="mixed")

    def test_omitted_sequence_stays_omitted(self):
        """
        BIP-370 reads an omitted PSBT_IN_SEQUENCE as 0xffffffff, which is exactly what
        embit hashes -- but embit fills the value in while parsing, so a re-serialized
        psbt would carry it explicitly and a coordinator would read that as a changed
        transaction. Splicing into the psbt's own bytes leaves it absent.
        """
        p = sp_psbt("01-sp-spend-1in")
        p.inputs[0].sequence = None
        raw = p.serialize()
        assert b"\x10" not in raw_maps(raw)[1]
        p = parse_kept(raw)
        assert p.inputs[0].sequence == 0xFFFFFFFF
        parse_testnet(p)
        silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        assert_signatures_verify(p)
        signed = silent_payments.psbt_bytes(p)
        assert b"\x10" not in raw_maps(signed)[1]
        assert_only_signatures_added(raw, signed, 1)

    def test_export_is_the_request_not_a_reserialization(self):
        """embit reorders the fields it writes, so the response has to be the request's
        own bytes: kiss-bdk compares what comes back against what it sent."""
        p = sp_psbt("01-sp-spend-1in")
        parse_testnet(p)
        silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        signed = silent_payments.psbt_bytes(p)
        assert strip_tap_key_sigs(signed) == a2b_base64(SP_SPEND_PSBTS["01-sp-spend-1in"])
        assert signed != p.serialize()

    def test_signing_without_the_original_bytes_is_refused(self):
        p = PSBT.parse(a2b_base64(SP_SPEND_PSBTS["01-sp-spend-1in"]))
        with pytest.raises(InvalidPSBTError) as e:
            parse_testnet(p)
        assert e.value.code == RejectCode.UNSUPPORTED_SILENT_PAYMENT
        silent_payments.remember_bytes(p, p.serialize()[:-1])
        with pytest.raises(ValueError):
            silent_payments.sign_spend_inputs(p, abandon_seed(), TESTNET)
        assert all(b"\x13" not in inp.unknown for inp in p.inputs)

    @pytest.mark.parametrize("change", [
        "sequence zero", "min time", "min height", "no tx version",
    ])
    def test_fields_embit_would_not_hash_as_written_are_refused(self, change):
        """
        embit builds the hashed transaction with `sequence or 0xffffffff` and
        `tx_version or 2`, and ignores BIP-370's per-input lock times. Each of those
        would sign a transaction other than the one the psbt describes. (An existing
        signature would make the count of new ones meaningless.)
        """
        p = sp_psbt("01-sp-spend-1in")
        inp = p.inputs[0]
        if change == "sequence zero":
            inp.sequence = 0
        elif change == "min time":
            inp.unknown[b"\x11"] = (500_000_000).to_bytes(4, "little")
        elif change == "min height":
            inp.unknown[b"\x12"] = (100).to_bytes(4, "little")
        else:
            p.tx_version = None
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT)

    @pytest.mark.parametrize("change", [
        "orphan spend key", "orphan tweak", "two spend keys", "short tweak", "long tweak",
        "ragged path", "no fingerprint", "invalid point", "short spend key",
    ])
    def test_malformed_fields_refused(self, change):
        p = sp_psbt("01-sp-spend-1in")
        inp = p.inputs[0]
        key = spend_key_field(inp)
        if change == "orphan spend key":
            del inp.unknown[b"\x20"]
        elif change == "orphan tweak":
            del inp.unknown[key]
        elif change == "two spend keys":
            inp.unknown[b"\x1f" + bytes.fromhex(KISS_KEYS[TESTNET][0])] = inp.unknown[key]
        elif change == "short tweak":
            inp.unknown[b"\x20"] = bytes(31)
        elif change == "long tweak":
            inp.unknown[b"\x20"] += b"\x00"
        elif change == "ragged path":
            inp.unknown[key] += b"\x00"
        elif change == "no fingerprint":
            inp.unknown[key] = b"\x73\xc5\xda"
        elif change == "invalid point":
            inp.unknown[b"\x1f\x02" + bytes(32)] = inp.unknown.pop(key)
        else:
            inp.unknown[key[:-1]] = inp.unknown.pop(key)
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="malformed")

    @pytest.mark.parametrize("change", [
        "parity flipped", "other key", "mainnet path", "account 1", "receive branch", "short path", "p2wpkh utxo",
    ])
    def test_claims_naming_this_seed_that_fail_are_refused(self, change):
        p = sp_psbt("01-sp-spend-1in")
        inp = p.inputs[0]
        key = spend_key_field(inp)
        origin = inp.unknown[key]
        path = lambda *idx: origin[:4] + b"".join(i.to_bytes(4, "little") for i in idx)
        H = 0x80000000
        if change == "parity flipped":
            assert key[1] == 0x02
            inp.unknown[b"\x1f\x03" + key[2:]] = inp.unknown.pop(key)
        elif change == "other key":
            inp.unknown[b"\x1f" + bytes.fromhex(KISS_KEYS[TESTNET][0])] = inp.unknown.pop(key)
        elif change == "mainnet path":
            inp.unknown[key] = path(H + 352, H + 0, H, H, 0)
        elif change == "account 1":
            inp.unknown[key] = path(H + 352, H + 1, H + 1, H, 0)
        elif change == "receive branch":
            inp.unknown[key] = path(H + 352, H + 1, H, H + 1, 0)
        elif change == "short path":
            inp.unknown[key] = path(H + 352, H + 1, H)
        else:
            inp.witness_utxo.script_pubkey = script.Script(b"\x00\x14" + bytes(20))
        assert_refused(p, RejectCode.FOREIGN_SILENT_PAYMENT)

    def test_another_seeds_inputs_mean_choose_another_seed(self):
        p = sp_psbt("02-sp-spend-2in")
        other = abandon_seed("TREZOR")
        assert_refused(p, RejectCode.SEED_CANNOT_SIGN, seed=other)
        assert not PSBTParser.has_matching_input_fingerprint(p, other, TESTNET)
        assert PSBTParser.has_matching_input_fingerprint(p, abandon_seed(), TESTNET)

    def test_partly_another_seeds_inputs_refused(self):
        p = sp_psbt("02-sp-spend-2in")
        inp = p.inputs[1]
        key = spend_key_field(inp)
        inp.unknown[key] = bytes.fromhex(abandon_seed("TREZOR").get_fingerprint(TESTNET)) + inp.unknown[key][4:]
        assert_refused(p, RejectCode.FOREIGN_SILENT_PAYMENT)

    @pytest.mark.parametrize("signer", ["wif", "child-xprv", "electrum", "regtest"])
    def test_unsupported_signers_refused(self, signer, monkeypatch):
        from seedsigner.models.wif import WIFKey
        monkeypatch.setattr(silent_payments, "spend_signing_key", MagicMock(side_effect=AssertionError("derived")))
        p = reparse(sp_psbt("01-sp-spend-1in"))
        network = TESTNET
        if signer == "wif":
            seed = WIFKey(ec.PrivateKey(b"\x01" * 32, network=NETWORKS["test"]).wif())
        elif signer == "child-xprv":
            seed = child_xprv_seed()
        elif signer == "electrum":
            seed = ElectrumSeed(ELECTRUM_MNEMONIC.split())
        else:
            seed, network = abandon_seed(), REGTEST
        with pytest.raises(InvalidPSBTError) as e:
            PSBTParser(p, seed=seed, network=network)
        assert e.value.code == RejectCode.UNSUPPORTED_SILENT_PAYMENT

    def test_seedless_parse_refused(self):
        p = reparse(sp_psbt("01-sp-spend-1in"))
        with pytest.raises(InvalidPSBTError) as e:
            PSBTParser(p).parse()
        assert e.value.code == RejectCode.UNSUPPORTED_SILENT_PAYMENT

    @pytest.mark.parametrize("key", [b"\x13x", b"\x20\x00", b"\x1cx", b"\xfcfake", b"\x11\x12"])
    def test_unexpected_input_fields_refused(self, key):
        """
        A key whose type byte is one embit reads, but whose length is not, is a field
        this signer would skip and a strict coordinator would read: no BIP-376 input
        carries anything but its own two fields.
        """
        p = sp_psbt("01-sp-spend-1in")
        p.inputs[0].unknown[key] = b"\x00" * 4
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT)

    @pytest.mark.parametrize("key", [b"\x04x", b"\x06\x00", b"\xfcfake", b"\x07x"])
    def test_unexpected_global_fields_refused(self, key):
        p = sp_psbt("01-sp-spend-1in")
        p.unknown[key] = b"\x00" * 4
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT)

    @pytest.mark.parametrize("flags", [b"\x01", b"\x02", b"\x04", b"\x80"])
    def test_any_modifiable_flag_refused(self, flags):
        """Not just the input/output bits: a coordinator rejects a response whose
        PSBT_GLOBAL_TX_MODIFIABLE is anything but zero."""
        p = sp_psbt("01-sp-spend-1in")
        p.unknown[b"\x06"] = flags
        assert_refused(p, RejectCode.TX_MODIFIABLE)

    @pytest.mark.parametrize("field", [
        "partial sig", "final scriptsig", "final scriptwitness", "tap key sig",
        "tap script sig", "tap leaf script", "tap bip32 derivation",
        "tap internal key", "tap merkle root",
    ])
    def test_inputs_carrying_signature_or_script_data_refused(self, field):
        """
        Anything already signed, finalized or built for a script path would make the
        count of new signatures meaningless, or come back as a response the coordinator
        refuses. A BIP-376 input is a bare key-path spend.
        """
        from embit.script import Witness

        p = sp_psbt("01-sp-spend-1in")
        inp = p.inputs[0]
        pub = ec.PrivateKey(b"\x01" * 32).get_public_key()
        if field == "partial sig":
            inp.partial_sigs[pub] = b"\x30" * 71 + b"\x01"
        elif field == "final scriptsig":
            inp.final_scriptsig = script.Script(b"\x51")
        elif field == "final scriptwitness":
            inp.final_scriptwitness = Witness([bytes(64)])
        elif field == "tap key sig":
            inp.unknown[b"\x13"] = bytes(64)
        elif field == "tap script sig":
            inp.taproot_sigs[(pub, bytes(32))] = bytes(64)
        elif field == "tap leaf script":
            inp.taproot_scripts[b"\xc0" + bytes(32)] = b"\x51\xc0"
        elif field == "tap bip32 derivation":
            inp.taproot_bip32_derivations[pub] = ([], DerivationPath(bytes(4), [0]))
        elif field == "tap internal key":
            inp.taproot_internal_key = pub
        else:
            inp.taproot_merkle_root = bytes(32)
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT)

    def test_taproot_change_refused_todays_way(self):
        """PR 2 signs spends with no change back to this seed; tr() change stays unreachable."""
        p = sp_psbt("01-sp-spend-1in")
        root = abandon_seed().get_root(TESTNET)
        change = root.derive("m/86h/1h/0h/1/0")
        out = p.outputs[1]
        out.bip32_derivations.clear()
        out.script_pubkey = script.p2tr(change.get_public_key())
        out.taproot_bip32_derivations[change.get_public_key()] = (
            [], DerivationPath(root.my_fingerprint, bip32.parse_path("m/86h/1h/0h/1/0")))
        assert_refused(p, RejectCode.UNREACHABLE_CHANGE_PATH)


def spend_secrets() -> list[str]:
    """b_spend, and d for every input of the fixtures, as hex."""
    b = b_spend()
    secrets = [b.to_bytes(32, "big").hex()]
    for tweak in (0x01, 0x02, 0x77):
        secrets.append(((b + int.from_bytes(bytes([tweak]) * 32, "big")) % SECP_N).to_bytes(32, "big").hex())
    return secrets


class TestSpendFlow(FlowTest):
    def _scan(self, name):
        def scan(view):
            view.decoder.add_data(SP_SPEND_PSBTS[name])
        return scan

    @pytest.mark.parametrize("name", SIGNED_FIXTURES)
    def test_scan_to_signed_qr(self, name, caplog, monkeypatch):
        from seedsigner.models import encode_qr

        caplog.set_level(logging.DEBUG)
        monkeypatch.setattr(PSBT, "sign_with", MagicMock(side_effect=AssertionError("sign_with()")))
        encoded = []
        class RecordingEncoder(encode_qr.UrPsbtQrEncoder):
            def __post_init__(self):
                super().__post_init__()
                # What the QR actually carries, which is the psbt's own bytes.
                encoded.append(silent_payments.psbt_bytes(self.psbt))
        monkeypatch.setattr(encode_qr, "UrPsbtQrEncoder", RecordingEncoder)

        self.settings.set_value(SettingsConstants.SETTING__NETWORK, TESTNET)
        self.controller.storage.seeds = [abandon_seed()]
        seen = []
        def record(view):
            seen.append(repr(vars(view)))
            seen.append(repr([(d.View_cls.__name__, d.view_args) for d in view.controller.back_stack]))

        num_outputs = len(sp_psbt(name).outputs)
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=self._scan(name)),
            FlowStep(psbt_views.PSBTSelectSeedView, before_run=record, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, before_run=record, screen_return_value=0),
            FlowStep(psbt_views.PSBTNoChangeWarningView, before_run=record, screen_return_value=0),
            FlowStep(psbt_views.PSBTMathView, before_run=record, screen_return_value=0),
        ] + [
            FlowStep(psbt_views.PSBTAddressDetailsView, before_run=record, screen_return_value=0)
            for _ in range(num_outputs)
        ] + [
            FlowStep(psbt_views.PSBTFinalizeView, before_run=record, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView, before_run=record, screen_return_value=0),
            FlowStep(MainMenuView),
        ])
        seen.append(repr([(d.View_cls.__name__, d.view_args) for d in self.controller.back_stack]))

        assert len(encoded) == 1
        signed = PSBT.parse(encoded[0])
        assert_signatures_verify(signed)
        assert_only_signatures_added(a2b_base64(SP_SPEND_PSBTS[name]), encoded[0], len(signed.inputs))

        logs = [r.getMessage() for r in caplog.records]
        assert any("signatures added" in line for line in logs)
        for secret in spend_secrets():
            assert not [line for line in logs if secret in line]
            assert not [entry for entry in seen if secret in entry]

    def test_foreign_tweak_refused_in_the_flow(self, monkeypatch):
        monkeypatch.setattr(silent_payments, "sign_spend_inputs", MagicMock(side_effect=AssertionError("signed")))
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, TESTNET)
        self.controller.storage.seeds = [abandon_seed()]

        def assert_code(view):
            assert view.code == RejectCode.FOREIGN_SILENT_PAYMENT

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=self._scan("04-sp-spend-foreign-tweak")),
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
            FlowStep(psbt_views.PSBTRefusalView, before_run=assert_code, screen_return_value=0),
            FlowStep(MainMenuView),
        ])
        assert self.controller.psbt is None

    @pytest.mark.parametrize("card", ["SATOCHIP", "KEYCARD"])
    def test_card_refused_before_connecting(self, card, monkeypatch):
        from seedsigner.helpers import seedkeeper_utils
        monkeypatch.setattr(seedkeeper_utils, "init_satochip", MagicMock(side_effect=AssertionError("card connected")))
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, TESTNET)
        self.settings.set_value(SettingsConstants.SETTING__SATOCHIP_SUPPORT, SettingsConstants.OPTION__ENABLED)
        self.settings.set_value(SettingsConstants.SETTING__KEYCARD_SUPPORT, SettingsConstants.OPTION__ENABLED)
        self.controller.storage.seeds = [abandon_seed()]

        def assert_code(view):
            assert view.code == RejectCode.UNSUPPORTED_SILENT_PAYMENT

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=self._scan("01-sp-spend-1in")),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=getattr(psbt_views.PSBTSelectSeedView, card)),
            FlowStep(psbt_views.PSBTRefusalView, before_run=assert_code, screen_return_value=0),
            FlowStep(MainMenuView),
        ])
