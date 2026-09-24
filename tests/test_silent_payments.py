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
import csv
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

    @pytest.mark.parametrize("scope, key, match", [
        ("global", b"\x07" + bytes.fromhex(KISS_KEYS[TESTNET][0]), "no Silent Payment output"),
        ("global", b"\x08" + bytes.fromhex(KISS_KEYS[TESTNET][0]), "no Silent Payment output"),
        ("input", b"\x1d" + bytes.fromhex(KISS_KEYS[TESTNET][0]), "no Silent Payment output"),
        ("input", b"\x1e" + bytes.fromhex(KISS_KEYS[TESTNET][0]), "no Silent Payment output"),
        ("output", b"\x09", "malformed Silent Payment field"),
        ("output", b"\x0a", "label but no keys"),
    ])
    def test_send_fields_refused_before_the_output_check(self, scope, key, match):
        """
        A BIP-375 field that cannot be acted on is refused first, even on a psbt whose
        output has no script: a send legitimately arrives without one, so the reason
        the user sees must be the field, not the missing script.
        """
        p = sp_psbt("01-sp-spend-1in")
        p.outputs[0].script_pubkey = None
        {"global": p, "input": p.inputs[0], "output": p.outputs[1]}[scope].unknown[key] = b"\x01" * 33
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match=match)

    def test_send_fields_refused_on_ordinary_psbt(self):
        """A Silent Payment output whose keys are the wrong length is not a recipient."""
        p = parse_kept(a2b_base64(KISS_SPEND_VECTORS["even"][0]))
        for key in list(p.inputs[0].unknown):
            del p.inputs[0].unknown[key]
        p.outputs[0].unknown[b"\x09"] = b"\x01" * 33
        assert_refused(p, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="malformed Silent Payment field")

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


# ---- BIP-375: sending to a Silent Payment address ------------------------------------

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def data_file(name: str):
    with open(os.path.join(DATA_DIR, name)) as f:
        return json.load(f) if name.endswith(".json") else list(csv.DictReader(f))


def hex_point(value: str) -> ec.PublicKey:
    return ec.PublicKey.parse(bytes.fromhex(value))


def bip374_prove(a: int, b: tuple, k: int, generator: tuple, message: bytes) -> bytes:
    """BIP-374 GenerateProof with k given, written out here so the check owes nothing
    to the helper: proof = bytes(32, e) || bytes(32, s)."""
    def cbytes(point):
        return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")

    a_point, c_point = _point_mul(generator, a), _point_mul(b, a)
    r1, r2 = _point_mul(generator, k), _point_mul(b, k)
    challenge = _tagged_hash(
        "BIP0374/challenge",
        cbytes(a_point) + cbytes(b) + cbytes(c_point) + cbytes(generator) + cbytes(r1) + cbytes(r2) + message,
    )
    e = int.from_bytes(challenge, "big") % SECP_N
    s = (k + e * a) % SECP_N
    return e.to_bytes(32, "big") + s.to_bytes(32, "big")


class TestDleqVectors:
    """
    BIP-374's own generate and verify vectors, unmodified, from
    bitcoin/bips/bip-0374. They pass the generator point in, so the helper takes one
    too; every device path uses secp256k1's own G.
    """
    @pytest.mark.parametrize("row", data_file("bip374_generate_proof_vectors.csv"),
                             ids=lambda row: row["comment"])
    def test_generate(self, row):
        if row["point_B"] == "INFINITY":
            # The point at infinity has no compressed encoding, so it cannot reach the
            # helper: the vector states it in words, and there is nothing to parse.
            with pytest.raises(ValueError):
                bytes.fromhex(row["point_B"])
            return
        secret = bytes.fromhex(row["scalar_a"])
        aux = bytes.fromhex(row["auxrand_r"])
        message = bytes.fromhex(row["message"])
        if row["result_proof"] == "INVALID":
            with pytest.raises(ValueError):
                silent_payments.dleq_prove(
                    secret, hex_point(row["point_B"]), aux, message=message,
                    generator=hex_point(row["point_G"]),
                )
            return
        proof = silent_payments.dleq_prove(
            secret, hex_point(row["point_B"]), aux, message=message,
            generator=hex_point(row["point_G"]),
        )
        assert proof.hex() == row["result_proof"]

    @pytest.mark.parametrize("row", data_file("bip374_verify_proof_vectors.csv"),
                             ids=lambda row: row["comment"])
    def test_verify(self, row):
        verified = silent_payments.dleq_verify(
            hex_point(row["point_A"]), hex_point(row["point_B"]), hex_point(row["point_C"]),
            bytes.fromhex(row["proof"]), message=bytes.fromhex(row["message"]),
            generator=hex_point(row["point_G"]),
        )
        assert verified is (row["result_success"] == "TRUE")

    def test_proof_is_bound_to_its_randomness(self):
        """Two proofs of the same statement differ, and each one verifies."""
        secret = bytes.fromhex("11" * 32)
        b_point = ec.PrivateKey(bytes.fromhex("22" * 32)).get_public_key()
        a_point = ec.PrivateKey(secret).get_public_key()
        share = silent_payments.ecdh_share(secret, b_point)
        first = silent_payments.dleq_prove(secret, b_point, bytes.fromhex("33" * 32))
        second = silent_payments.dleq_prove(secret, b_point, bytes.fromhex("44" * 32))
        assert first != second
        for proof in (first, second):
            assert len(proof) == 64
            assert silent_payments.dleq_verify(a_point, b_point, share, proof)

    def test_a_tampered_share_is_refused(self):
        secret = bytes.fromhex("11" * 32)
        b_point = ec.PrivateKey(bytes.fromhex("22" * 32)).get_public_key()
        a_point = ec.PrivateKey(secret).get_public_key()
        proof = silent_payments.dleq_prove(secret, b_point, bytes.fromhex("33" * 32))
        other = silent_payments.ecdh_share(bytes.fromhex("55" * 32), b_point)
        assert not silent_payments.dleq_verify(a_point, b_point, other, proof)

    def test_the_proof_matches_an_independent_implementation(self):
        """The helper's proof against BIP-374 written out in this file, nonce included."""
        secret = bytes.fromhex("0f" + "3c" * 31)
        b_secret = bytes.fromhex("77" * 32)
        aux = bytes.fromhex("5a" * 32)
        b_point = ec.PrivateKey(b_secret).get_public_key()
        a = int.from_bytes(secret, "big")
        b = _point_mul(SECP_G, int.from_bytes(b_secret, "big"))

        def cbytes(point):
            return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")

        tweaked = bytes(x ^ y for x, y in zip(secret, _tagged_hash("BIP0374/aux", aux)))
        rand = _tagged_hash(
            "BIP0374/nonce", tweaked + cbytes(_point_mul(SECP_G, a)) + cbytes(_point_mul(b, a))
        )
        k = int.from_bytes(rand, "big") % SECP_N

        assert silent_payments.dleq_prove(secret, b_point, aux) == bip374_prove(a, b, k, SECP_G, b"")

    def test_the_pure_python_curve_agrees_with_the_library(self, monkeypatch):
        """
        A device without libsecp256k1 runs the same maths through embit's own pure
        curve, so every point this module computes must come out the same either way.
        """
        secret = bytes.fromhex("0f" + "3c" * 31)
        b_point = ec.PrivateKey(bytes.fromhex("77" * 32)).get_public_key()
        a_point = ec.PrivateKey(secret).get_public_key()
        aux = bytes.fromhex("5a" * 32)
        with_library = (silent_payments.ecdh_share(secret, b_point).sec(),
                        silent_payments.dleq_prove(secret, b_point, aux))

        monkeypatch.delattr(silent_payments.secp256k1, "ec_pubkey_tweak_mul", raising=False)
        pure = (silent_payments.ecdh_share(secret, b_point).sec(),
                silent_payments.dleq_prove(secret, b_point, aux))
        assert pure == with_library
        assert silent_payments.dleq_verify(a_point, b_point,
                                          silent_payments.ecdh_share(secret, b_point), pure[1])


# A coordinator's request, written out field by field so the bytes the device answers
# with can be compared against bytes this file produced, not against embit's output.

SEND_PATHS = {
    "p2tr": "m/86h/1h/0h/0/0",
    "p2wpkh": "m/84h/1h/0h/0/0",
    "p2sh-p2wpkh": "m/49h/1h/0h/0/0",
    "p2pkh": "m/44h/1h/0h/0/0",
}


def write_map(fields: dict) -> bytes:
    out = bytearray()
    for key, value in fields.items():
        out += compact.to_bytes(len(key)) + key
        out += compact.to_bytes(len(value)) + value
    return bytes(out) + b"\x00"


def path_field(fingerprint: bytes, path: list) -> bytes:
    return fingerprint + b"".join(i.to_bytes(4, "little") for i in path)


def prevout_script(kind: str, key) -> script.Script:
    pkh = hashlib.new("ripemd160", hashlib.sha256(key.sec()).digest()).digest()
    if kind == "p2tr":
        return script.Script(b"\x51\x20" + key.taproot_tweak(b"").xonly())
    if kind == "p2wpkh":
        return script.Script(b"\x00\x14" + pkh)
    if kind == "p2sh-p2wpkh":
        redeem = b"\x00\x14" + pkh
        return script.Script(b"\xa9\x14" + hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest() + b"\x87")
    return script.Script(b"\x76\xa9\x14" + pkh + b"\x88\xac")


def send_request(kind: str = "p2wpkh", recipients: list = None, ordinary_outputs: list = None,
                 seed=None, network=TESTNET, inputs: int = 1, modifiable: int = 0x03,
                 sighash: int = None, extra_input_fields: dict = None) -> bytes:
    """
    A BIP-375 request: `inputs` inputs of one kind belonging to `seed`, and one output
    per (scan key, spend key, label) in `recipients` with no script yet.
    """
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    seed = seed or abandon_seed()
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(seed.mnemonic_list)))
    derived = root.derive(SEND_PATHS[kind])
    key, fingerprint = derived.key, root.my_fingerprint
    path = bip32.parse_path(SEND_PATHS[kind])
    spk = prevout_script(kind, key)
    pkh = hashlib.new("ripemd160", hashlib.sha256(key.sec()).digest()).digest()

    # Each input covers its share of the outputs plus a plausible fee, so the flow is an
    # ordinary transaction and not one the risk screens stop.
    spent = 10_000 * len(recipients or []) + sum(value for value, _ in (ordinary_outputs or []))
    input_value = (spent + 1_000 + inputs - 1) // inputs

    global_fields = {
        b"\x02": (2).to_bytes(4, "little"),
        b"\x04": compact.to_bytes(inputs),
        b"\x05": compact.to_bytes(len(recipients or []) + len(ordinary_outputs or [])),
        b"\xfb": (2).to_bytes(4, "little"),
    }
    if modifiable is not None:
        global_fields[b"\x06"] = bytes([modifiable])
    raw = bytearray(b"psbt\xff") + write_map(global_fields)

    for index in range(inputs):
        prev = Transaction(version=2, vin=[TransactionInput(bytes([0x11 + index]) * 32, 0)],
                           vout=[TransactionOutput(input_value, spk)])
        fields = {}
        if kind == "p2pkh":
            fields[b"\x00"] = prev.serialize()
        else:
            fields[b"\x01"] = TransactionOutput(input_value, spk).serialize()
        if sighash is not None:
            fields[b"\x03"] = sighash.to_bytes(4, "little")
        if kind == "p2sh-p2wpkh":
            fields[b"\x04"] = b"\x00\x14" + pkh
        if kind == "p2tr":
            fields[b"\x16" + key.xonly()] = compact.to_bytes(0) + path_field(fingerprint, path)
        else:
            fields[b"\x06" + key.sec()] = path_field(fingerprint, path)
        # PSBT_IN_PREVIOUS_TXID is the txid as the transaction serializes it, which is
        # the reverse of the order embit's txid() prints.
        fields[b"\x0e"] = bytes(reversed(prev.txid()))
        fields[b"\x0f"] = (0).to_bytes(4, "little")
        fields[b"\x10"] = (0xFFFFFFFD).to_bytes(4, "little")
        fields.update(extra_input_fields or {})
        raw += write_map(fields)

    for scan, spend, label in (recipients or []):
        fields = {b"\x03": (10_000).to_bytes(8, "little"), b"\x09": scan + spend}
        if label is not None:
            fields[b"\x0a"] = label.to_bytes(4, "little")
        raw += write_map(fields)
    for value, output_script in (ordinary_outputs or []):
        raw += write_map({b"\x03": value.to_bytes(8, "little"), b"\x04": output_script})
    return bytes(raw)


def rebuild(maps: list) -> bytes:
    """A psbt's maps written back out, so a patched field's length stays right."""
    return b"psbt\xff" + b"".join(write_map(m) for m in maps)


def labeled_spend_key(seed, m: int, network=TESTNET) -> bytes:
    """A recipient's B_m for label m, derived here rather than through the helper."""
    scan, spend = silent_payments._keys(seed, network)
    tweak = _tagged_hash("BIP0352/Label", scan.secret + m.to_bytes(4, "big"))
    point = _point_add(_lift_x(spend.get_public_key().sec()),
                       _point_mul(SECP_G, int.from_bytes(tweak, "big")))
    return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")


def sp_keys(seed=None, network=TESTNET) -> tuple:
    """A seed's (scan public key, spend public key), as a coordinator writes them."""
    scan, spend = silent_payments._keys(seed or abandon_seed(), network)
    return scan.get_public_key().sec(), spend.get_public_key().sec()


def stranger_seed() -> Seed:
    return Seed(["zoo"] * 11 + ["wrong"])


def change_code(seed=None, network=TESTNET) -> tuple:
    """This wallet's own change code: its scan key and its label-0 spend key."""
    seed = seed or abandon_seed()
    return sp_keys(seed, network)[0], silent_payments._label_zero_spend_key(seed, network)


def parsed_send(raw: bytes, seed=None, network=TESTNET) -> tuple:
    p = parse_kept(raw)
    parser = PSBTParser(p, seed=seed or abandon_seed(), network=network)
    return p, parser


def expected_send_scripts(raw: bytes, seed=None, network=TESTNET) -> list:
    """
    Every Silent Payment output's script, derived here from the request alone: the sum
    of the input keys, BIP-352's input hash, and t_k for the k BIP-375 gives each code.
    """
    seed = seed or abandon_seed()
    p = PSBT.parse(raw)
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(seed.mnemonic_list)))
    secrets = []
    for inp in p.inputs:
        utxo = inp.utxo
        data = utxo.script_pubkey.data
        if len(data) == 34 and data[0] == 0x51:
            pub, (_leaves, der) = list(inp.taproot_bip32_derivations.items())[0]
            d = int.from_bytes(root.derive(der.derivation).key.taproot_tweak(b"").secret, "big")
            secrets.append(d if not has_odd_y(d) else SECP_N - d)
        else:
            der = list(inp.bip32_derivations.values())[0]
            secrets.append(int.from_bytes(root.derive(der.derivation).key.secret, "big"))
    a = sum(secrets) % SECP_N
    a_point = _point_mul(SECP_G, a)
    outpoints = [bytes(inp.txid)[::-1] + inp.vout.to_bytes(4, "little") for inp in p.inputs]

    def cbytes(point):
        return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")

    ih = _tagged_hash("BIP0352/Inputs", min(outpoints) + cbytes(a_point))
    scripts, counters = {}, {}
    for index, out in enumerate(p.outputs):
        info = out.unknown.get(b"\x09")
        if not info:
            continue
        scan, spend = info[:33], info[33:]
        k = counters.get(scan, 0)
        counters[scan] = k + 1
        share = _point_mul(_lift_x(scan), a)
        shared = _point_mul(share, int.from_bytes(ih, "big"))
        t = _tagged_hash("BIP0352/SharedSecret", cbytes(shared) + k.to_bytes(4, "big"))
        output = _point_add(_lift_x(spend), _point_mul(SECP_G, int.from_bytes(t, "big")))
        scripts[index] = b"\x51\x20" + output[0].to_bytes(32, "big")
    return scripts


def _lift_x(sec: bytes) -> tuple:
    """A compressed public key as a point, without embit."""
    x = int.from_bytes(sec[1:], "big")
    y = pow((pow(x, 3, SECP_P) + 7) % SECP_P, (SECP_P + 1) // 4, SECP_P)
    if y * y % SECP_P != (pow(x, 3, SECP_P) + 7) % SECP_P:
        raise ValueError("not on the curve")
    return x, y if y % 2 == sec[0] % 2 else SECP_P - y


KINDS = ["p2tr", "p2wpkh", "p2sh-p2wpkh", "p2pkh"]


class TestSendPreparation:
    @pytest.mark.parametrize("kind", KINDS)
    def test_the_output_script_is_computed_and_the_transaction_locked(self, kind):
        raw = send_request(kind, [sp_keys(stranger_seed()) + (None,)])
        p, parser = parsed_send(raw)
        share_type, dleq_type = silent_payments.SEND_KEY_TYPES["global"]
        scan = sp_keys(stranger_seed())[0]

        assert p.outputs[0].script_pubkey.data == expected_send_scripts(raw)[0]
        assert bytes([share_type]) + scan in p.unknown
        assert bytes([dleq_type]) + scan in p.unknown
        assert p.unknown[b"\x06"] == b"\x00"
        assert PSBTParser.sig_count(p) == 0
        assert parser.silent_payment_send
        assert parser.silent_payment_recipients[0]["address"].startswith("tsp1")
        assert parser.silent_payment_recipients[0]["change"] is False

    def test_the_share_and_proof_verify_against_the_input_keys(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)], inputs=2)
        p, _ = parsed_send(raw)
        scan = sp_keys(stranger_seed())[0]
        share = ec.PublicKey.parse(p.unknown[b"\x07" + scan])
        proof = p.unknown[b"\x08" + scan]

        secrets = []
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(ABANDON)))
        for inp in p.inputs:
            der = list(inp.bip32_derivations.values())[0]
            secrets.append(int.from_bytes(root.derive(der.derivation).key.secret, "big"))
        a = sum(secrets) % SECP_N
        a_point = ec.PrivateKey(a.to_bytes(32, "big")).get_public_key()
        assert share.sec() == silent_payments.ecdh_share(a.to_bytes(32, "big"),
                                                         ec.PublicKey.parse(scan)).sec()
        assert silent_payments.dleq_verify(a_point, ec.PublicKey.parse(scan), share, proof)

    def test_a_second_payment_to_the_same_address_gets_the_next_k(self):
        code = sp_keys(stranger_seed())
        raw = send_request("p2wpkh", [code + (None,), code + (None,)])
        p, _ = parsed_send(raw)
        expected = expected_send_scripts(raw)
        assert [out.script_pubkey.data for out in p.outputs] == [expected[0], expected[1]]
        assert p.outputs[0].script_pubkey.data != p.outputs[1].script_pubkey.data

    def test_change_to_our_own_label_zero_address_is_change(self):
        scan, spend = change_code()
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,), (scan, spend, 0)])
        _, parser = parsed_send(raw)
        assert [r["change"] for r in parser.silent_payment_recipients] == [False, True]
        assert parser.silent_payment_recipients[1]["address"] == silent_payments._bech32m(
            "tsp", scan + spend)

    def test_our_scan_key_without_the_label_zero_key_is_not_change(self):
        """A claim of change is checked against both keys, not the scan key alone."""
        scan, _ = change_code()
        spend = sp_keys()[1]
        raw = send_request("p2wpkh", [(scan, spend, 0)])
        _, parser = parsed_send(raw)
        assert parser.silent_payment_recipients[0]["change"] is False

    def test_a_label_on_someone_elses_code_is_not_change(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (0,)])
        _, parser = parsed_send(raw)
        assert parser.silent_payment_recipients[0]["change"] is False

    def test_an_ordinary_output_is_left_alone(self):
        ordinary = script.p2wpkh(ec.PrivateKey(bytes.fromhex("42" * 32)).get_public_key()).data
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)],
                           ordinary_outputs=[(5_000, ordinary)])
        p, parser = parsed_send(raw)
        assert p.outputs[1].script_pubkey.data == ordinary
        assert len(parser.silent_payment_recipients) == 1

    def test_a_matching_script_already_in_the_request_is_accepted(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        expected = expected_send_scripts(raw)[0]
        maps = raw_maps(raw)
        request = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        filled = bytearray(request)
        # rewrite the output map with its script, as a coordinator that computed it would
        head = request[:request.index(maps[2][b"\x09"]) - 3]
        filled = bytearray(head) + write_map({
            b"\x03": (10_000).to_bytes(8, "little"),
            b"\x04": expected,
            b"\x09": maps[2][b"\x09"],
        })
        p, _ = parsed_send(bytes(filled))
        assert p.outputs[0].script_pubkey.data == expected


def undo_send_changes(response: bytes, request: bytes) -> bytes:
    """
    The response with everything BIP-375 lets this device add or change taken back
    out: the signatures, each sighash type, share, proof and output script the
    request did not carry, and the modifiable flags as they came in.

    What is left must be the request, byte for byte, or the device changed something
    it was not entitled to.
    """
    request_maps = raw_maps(request)
    inputs = int(request_maps[0][b"\x04"][0])
    global_before = request_maps[0].get(b"\x06")
    out = bytearray(response[:5])
    stream = BytesIO(response[5:])
    index = 0
    while stream.tell() < len(response) - 5:
        start = stream.tell()
        key = stream.read(compact.read_from(stream))
        if not key:
            out += response[5 + start:5 + stream.tell()]
            index += 1
            continue
        value = stream.read(compact.read_from(stream))
        record = response[5 + start:5 + stream.tell()]
        if index == 0:
            if key[0] in silent_payments.SEND_KEY_TYPES["global"] and key not in request_maps[0]:
                continue
            if key == b"\x06":
                if global_before is None:
                    continue
                record = (compact.to_bytes(len(key)) + key
                          + compact.to_bytes(len(global_before)) + global_before)
        elif 1 <= index <= inputs:
            if key == b"\x03" and b"\x03" in request_maps[index]:
                pass
            elif key[0] in (0x13, 0x02, 0x03):
                continue
        elif key == b"\x04" and b"\x04" not in request_maps[index]:
            continue
        out += record
    return bytes(out)


def signed_send(kind: str = "p2wpkh", recipients=None, seed=None, **kwargs) -> tuple:
    """A prepared and signed request, as (request bytes, psbt, response bytes)."""
    seed = seed or abandon_seed()
    recipients = recipients or [sp_keys(stranger_seed()) + (None,)]
    raw = send_request(kind, recipients, seed=seed, **kwargs)
    p, _ = parsed_send(raw, seed=seed)
    silent_payments.sign_send_inputs(p, seed, TESTNET)
    return raw, p, silent_payments.psbt_bytes(p)


class TestSendSigning:
    @pytest.mark.parametrize("kind", KINDS)
    def test_the_response_is_the_request_plus_only_what_is_allowed(self, kind):
        raw, p, signed = signed_send(kind)
        assert signed != raw
        assert undo_send_changes(signed, raw) == raw
        assert PSBTParser.sig_count(p) == 1

    @pytest.mark.parametrize("kind", KINDS)
    def test_every_input_is_signed_with_sighash_all(self, kind):
        raw, p, signed = signed_send(kind, inputs=2)
        maps = raw_maps(signed)
        for i in (1, 2):
            assert maps[i][b"\x03"] == (0x01).to_bytes(4, "little")
        assert PSBTParser.sig_count(p) == 2

    def test_a_taproot_signature_is_65_bytes_and_verifies(self):
        raw, p, signed = signed_send("p2tr")
        signature = raw_maps(signed)[1][b"\x13"]
        assert len(signature) == 65 and signature[64] == 0x01
        reparsed = PSBT.parse(signed)
        message = reparsed.sighash(0, sighash=SIGHASH.ALL)
        assert message != reparsed.sighash(0, sighash=SIGHASH.DEFAULT)
        output_key = reparsed.inputs[0].utxo.script_pubkey.data[2:]
        assert bip340_verify(output_key, message, signature[:64])

    @pytest.mark.parametrize("kind", ["p2wpkh", "p2sh-p2wpkh", "p2pkh"])
    def test_an_ordinary_signature_is_a_partial_sig_ending_in_01(self, kind):
        raw, p, signed = signed_send(kind)
        records = [(k, v) for k, v in raw_maps(signed)[1].items() if k[0] == 0x02]
        assert len(records) == 1
        (key, signature), = records
        assert len(key) == 34 and signature[-1] == 0x01
        reparsed = PSBT.parse(signed)
        message = reparsed.sighash(0, sighash=SIGHASH.ALL)
        assert ec.PublicKey.parse(key[1:]).verify(ec.Signature.parse(signature[:-1]), message)
        assert b"\x13" not in raw_maps(signed)[1]

    @pytest.mark.parametrize("kind", KINDS)
    def test_the_response_is_never_finalized(self, kind):
        """
        embit's sign_with() writes a key-path Taproot signature into
        PSBT_IN_FINAL_SCRIPTWITNESS, which is the coordinator's field, so a send does
        not go through it and no input comes back finalized.
        """
        raw = send_request(kind, [sp_keys(stranger_seed()) + (None,)])
        p, _ = parsed_send(raw)
        original = PSBT.sign_with
        try:
            PSBT.sign_with = MagicMock(side_effect=AssertionError("sign_with()"))
            silent_payments.sign_send_inputs(p, abandon_seed(), TESTNET)
        finally:
            PSBT.sign_with = original
        signed = silent_payments.psbt_bytes(p)
        assert all(key not in raw_maps(signed)[1] for key in (b"\x07", b"\x08"))
        assert PSBT.parse(signed).inputs[0].final_scriptwitness is None

    def test_signing_leaves_the_psbt_alone_when_an_input_is_not_ours(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        p, _ = parsed_send(raw)
        before = silent_payments.psbt_bytes(p)
        p.inputs[0].bip32_derivations.clear()
        with pytest.raises(ValueError):
            silent_payments.sign_send_inputs(p, abandon_seed(), TESTNET)
        assert silent_payments.psbt_bytes(p) == before
        assert PSBTParser.sig_count(p) == 0

    def test_a_signed_response_cannot_be_signed_again(self):
        raw, p, signed = signed_send("p2tr")
        assert_refused(parse_kept(signed), RejectCode.UNSUPPORTED_SILENT_PAYMENT,
                       match="already signed")

    def test_the_change_output_is_signed_like_any_other(self):
        scan, spend = change_code()
        raw, p, signed = signed_send(
            "p2wpkh", [sp_keys(stranger_seed()) + (None,), (scan, spend, 0)])
        assert undo_send_changes(signed, raw) == raw
        assert len([m for m in raw_maps(signed)[2:] if b"\x04" in m]) == 2


def refuse_send(raw: bytes, code: str, match: str = None, seed=None):
    with pytest.raises(InvalidPSBTError, match=match) as e:
        PSBTParser(parse_kept(raw), seed=seed or abandon_seed(), network=TESTNET)
    assert e.value.code == code
    return e.value


class TestSendRefusals:
    def test_an_input_of_another_wallet(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)], seed=stranger_seed())
        refuse_send(raw, RejectCode.FOREIGN_SILENT_PAYMENT, match="another wallet signs")

    def test_an_input_whose_derivation_does_not_give_the_prevout(self):
        """The prevout is what the check is against, not the derivation on its own."""
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        maps = raw_maps(raw)
        other = ec.PrivateKey(bytes.fromhex("5e" * 32)).get_public_key()
        stolen = b"\x00\x14" + hashlib.new("ripemd160", hashlib.sha256(other.sec()).digest()).digest()
        maps[1][b"\x01"] = maps[1][b"\x01"][:8] + compact.to_bytes(len(stolen)) + stolen
        refuse_send(rebuild(maps), RejectCode.FOREIGN_SILENT_PAYMENT, match="another wallet signs")

    def test_a_script_path_taproot_input(self):
        seed = abandon_seed()
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(ABANDON)))
        key = root.derive(SEND_PATHS["p2tr"]).key
        leaf = bytes.fromhex("77" * 32)
        raw = send_request("p2tr", [sp_keys(stranger_seed()) + (None,)], extra_input_fields={
            b"\x16" + key.xonly(): (compact.to_bytes(1) + leaf
                                    + path_field(root.my_fingerprint,
                                                 bip32.parse_path(SEND_PATHS["p2tr"]))),
        })
        refuse_send(raw, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="not a type")

    def test_a_taproot_leaf_script(self):
        """A leaf script means the output key may be spent through a script path."""
        raw = send_request("p2tr", [sp_keys(stranger_seed()) + (None,)],
                           extra_input_fields={b"\x15" + b"\x01" * 33: b"\x51"})
        refuse_send(raw, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="not a type")

    def test_an_ineligible_input_type(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        maps = raw_maps(raw)
        p2wsh = b"\x00\x20" + bytes.fromhex("9a" * 32)
        maps[1][b"\x01"] = maps[1][b"\x01"][:8] + compact.to_bytes(len(p2wsh)) + p2wsh
        refuse_send(rebuild(maps), RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="not a type")

    def test_inputs_of_more_than_one_kind(self):
        first = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)], inputs=2)
        taproot = raw_maps(send_request("p2tr", [sp_keys(stranger_seed()) + (None,)]))[1]
        maps = raw_maps(first)
        refuse_send(rebuild([maps[0], maps[1], taproot, maps[3]]), RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="more than one kind")

    def test_another_signers_ecdh_share(self):
        scan = sp_keys(stranger_seed())[0]
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)],
                           extra_input_fields={b"\x1d" + scan: b"\x02" + bytes(32)})
        refuse_send(raw, RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="another signer's ECDH share")

    @pytest.mark.parametrize("sighash", [0x00, 0x02, 0x03, 0x81])
    def test_a_sighash_that_is_not_all(self, sighash):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)], sighash=sighash)
        refuse_send(raw, RejectCode.UNSUPPORTED_SIGHASH, match="not SIGHASH_ALL")

    def test_an_explicit_sighash_all_is_accepted(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)], sighash=0x01)
        p, parser = parsed_send(raw)
        assert p.outputs[0].script_pubkey.data == expected_send_scripts(raw)[0]

    def test_an_output_script_that_pays_somewhere_else(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        maps = raw_maps(raw)
        elsewhere = b"\x51\x20" + bytes.fromhex("11" * 32)
        maps[2] = {b"\x03": maps[2][b"\x03"], b"\x04": elsewhere, b"\x09": maps[2][b"\x09"]}
        refuse_send(rebuild(maps), RejectCode.UNSUPPORTED_SILENT_PAYMENT,
                    match="already pays somewhere else")

    def test_an_ecdh_share_these_inputs_do_not_give(self):
        scan = sp_keys(stranger_seed())[0]
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        maps = raw_maps(raw)
        maps[0][b"\x07" + scan] = ec.PrivateKey(bytes.fromhex("31" * 32)).get_public_key().sec()
        refuse_send(rebuild(maps), RejectCode.UNSUPPORTED_SILENT_PAYMENT,
                    match="not the one these inputs give")

    def test_a_dleq_proof_that_does_not_hold(self):
        scan = sp_keys(stranger_seed())[0]
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        p, _ = parsed_send(raw)
        share = p.unknown[b"\x07" + scan]
        maps = raw_maps(raw)
        maps[0][b"\x07" + scan] = share
        maps[0][b"\x08" + scan] = bytes(64)
        refuse_send(rebuild(maps), RejectCode.UNSUPPORTED_SILENT_PAYMENT,
                    match="does not hold")

    def test_a_global_field_of_its_own(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        maps = raw_maps(raw)
        maps[0][b"\xfc\x04kiss"] = b"\x01"
        refuse_send(rebuild(maps), RejectCode.UNSUPPORTED_SILENT_PAYMENT,
                    match="global field of its own")

    def test_a_v0_psbt(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        maps = raw_maps(raw)
        del maps[0][b"\xfb"]
        refuse_send(rebuild(maps), RejectCode.UNSUPPORTED_SILENT_PAYMENT, match="v2 PSBT")

    def test_a_psbt_whose_own_bytes_were_not_kept(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        with pytest.raises(InvalidPSBTError, match="as received") as e:
            PSBTParser(PSBT.parse(raw), seed=abandon_seed(), network=TESTNET)
        assert e.value.code == RejectCode.UNSUPPORTED_SILENT_PAYMENT

    def test_a_seed_that_has_no_silent_payments_account(self):
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        with pytest.raises(InvalidPSBTError, match="Silent Payment") as e:
            PSBTParser(parse_kept(raw), seed=abandon_seed(), network=REGTEST)
        assert e.value.code == RejectCode.UNSUPPORTED_SILENT_PAYMENT


BIP352_SENDING = data_file("bip352_sending_vectors.json")
BIP375_VECTORS = data_file("bip375_psbt_vectors.json")

# BIP-375's own vectors assign k by output index, while its text sorts the codes
# lexicographically. The two differ only when one scan key has more than one spend key,
# which this device refuses for that reason (see TestSendRefusals).
BIP375_SHARED_SCAN_KEY = "label=3"


def sending_cases(with_outputs=True) -> list:
    cases = []
    for case in BIP352_SENDING:
        given = case["sending"][0]
        has = bool(given["expected"]["outputs"] and given["expected"]["outputs"][0])
        if has == with_outputs:
            cases.append(case)
    return cases


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


# BIP-341's NUMS point H. BIP-352 skips a Taproot input whose *internal* key is H,
# which the spender shows in the control block of a script-path spend; the output key
# is H tweaked by the merkle root, not H itself.
NUMS_POINT = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def taproot_internal_key(inp) -> bytes:
    """
    The x-only internal key an input states: PSBT_IN_TAP_INTERNAL_KEY, or the one in
    the control block of a leaf script (PSBT_IN_TAP_LEAF_SCRIPT, whose key is the
    control block: a leaf version byte, then the internal key). None if it states
    neither.
    """
    if inp.taproot_internal_key is not None:
        return inp.taproot_internal_key.xonly()
    for key in inp.taproot_scripts:
        if len(key) >= 33:
            return bytes(key[1:33])
    return None


def vector_input_key(inp):
    """
    What an input of a BIP-375 vector contributes to the shared secret, as
    (eligible, key): BIP-352's four types only, the NUMS exception applied to the
    internal key, and P2SH only when it wraps P2WPKH. `key` is None for an eligible
    input the vector never states a key for.

    A Taproot prevout gives its own output key, as BIP-352 says. For the other types
    it is the key the input declares, because these vectors' P2WPKH and P2SH prevouts
    do not hash to their own declared keys (hash160(02c817bb...) is 1e2ad787..., the
    prevout is 0014229a72d3...) -- which is also why this device refuses these vectors
    outright: see TestSendRefusals for the prevout check on requests built here.
    """
    utxo = inp.utxo if (inp.witness_utxo or inp.non_witness_utxo) else None
    if utxo is None:
        return False, None
    data = utxo.script_pubkey.data
    declared = [pub for pub in inp.bip32_derivations]
    declared += [ec.PublicKey.parse(b"\x02" + pub.xonly()) for pub in inp.taproot_bip32_derivations]
    if len(data) == 34 and data[:2] == b"\x51\x20":
        internal = taproot_internal_key(inp)
        if internal == NUMS_POINT:
            # BIP-352's exception: a script-path spend under H contributes nothing.
            return False, None
        if internal is None and data[2:] == NUMS_POINT:
            # This file's own shorthand for that case: the vector states no control
            # block and puts H in the output key instead. Kept, and named, rather
            # than left looking like the rule itself.
            return False, None
        return True, ec.PublicKey.parse(b"\x02" + data[2:])
    if len(data) == 22 and data[:2] == b"\x00\x14":
        return True, declared[0] if declared else None
    if len(data) == 23 and data[:2] == b"\xa9\x14":
        redeem = inp.redeem_script.data if inp.redeem_script else b""
        if len(redeem) != 22 or redeem[:2] != b"\x00\x14":
            # A P2SH input that wraps anything but P2WPKH, e.g. multisig.
            return False, None
        return True, declared[0] if declared else None
    if len(data) == 25 and data[:3] == b"\x76\xa9\x14" and data[23:] == b"\x88\xac":
        return True, declared[0] if declared else None
    return False, None


class TestBip352SendingVectors:
    """
    BIP-352's own sending vectors, the sending half of send_and_receive_test_vectors.json
    as bitcoin/bips publishes it. Each case's own input key sum is used, so what is under
    test is the derivation and not this file's idea of which inputs are eligible.
    """
    @pytest.mark.parametrize("case", sending_cases(), ids=lambda case: case["comment"][:48])
    def test_outputs(self, case):
        given = case["sending"][0]["given"]
        expected = case["sending"][0]["expected"]
        secret = bytes.fromhex(expected["input_private_key_sum"])
        outpoints = [bytes.fromhex(v["txid"])[::-1] + v["vout"].to_bytes(4, "little")
                     for v in given["vin"]]
        a_point = ec.PrivateKey(secret).get_public_key()
        hash_of_inputs = silent_payments.input_hash(outpoints, a_point)

        codes = [(bytes.fromhex(r["scan_pub_key"]), bytes.fromhex(r["spend_pub_key"]))
                 for r in given["recipients"]]
        shares = {scan: silent_payments.ecdh_share(secret, ec.PublicKey.parse(scan))
                  for scan, _ in codes}
        got = {silent_payments.output_script(shares[scan], ec.PublicKey.parse(spend),
                                            hash_of_inputs, k)[2:].hex()
               for (scan, spend), k in zip(codes, silent_payments.code_order(codes))}
        # BIP-352 lets the sender order a scan key's recipients as it likes, so the
        # vectors list every valid set; BIP-375 is what narrows it to one.
        assert any(got == set(alternative) for alternative in expected["outputs"])

    def test_the_shared_secret_of_each_group_matches(self):
        """The ECDH share itself, against the vectors' own shared_secrets."""
        for case in sending_cases():
            given, expected = case["sending"][0]["given"], case["sending"][0]["expected"]
            secret = bytes.fromhex(expected["input_private_key_sum"])
            outpoints = [bytes.fromhex(v["txid"])[::-1] + v["vout"].to_bytes(4, "little")
                         for v in given["vin"]]
            hash_of_inputs = silent_payments.input_hash(
                outpoints, ec.PrivateKey(secret).get_public_key())
            for recipient, shared in zip(given["recipients"], expected["shared_secrets"]):
                scan = ec.PublicKey.parse(bytes.fromhex(recipient["scan_pub_key"]))
                share = silent_payments.ecdh_share(secret, scan)
                tweaked = silent_payments._lincomb(
                    [(share, int.from_bytes(hash_of_inputs, "big"))])
                assert tweaked.sec().hex() == shared

    def test_input_keys_that_sum_to_zero_are_refused(self):
        case = next(c for c in BIP352_SENDING if "sum up to zero" in c["comment"])
        keys = [bytes.fromhex(v["private_key"]) for v in case["sending"][0]["given"]["vin"]]
        with pytest.raises(ValueError, match="sum to zero"):
            silent_payments.secret_sum(keys)

    def test_an_intermediate_sum_of_zero_is_fine(self):
        case = next(c for c in BIP352_SENDING if "intermediate sum is zero" in c["comment"])
        given, expected = case["sending"][0]["given"], case["sending"][0]["expected"]
        keys = []
        for vin in given["vin"]:
            secret = bytes.fromhex(vin["private_key"])
            taproot = vin["prevout"]["scriptPubKey"]["hex"].startswith("5120")
            keys.append(silent_payments.even_y_secret(secret) if taproot else secret)
        assert silent_payments.secret_sum(keys).hex() == expected["input_private_key_sum"]

    def test_the_group_limit_is_enforced(self):
        """
        BIP-352 fails a group of more than K_max payments to one scan key, which bounds
        what a receiver has to scan. The vector's own recipient list is generated rather
        than written out, so the limit is exercised directly.
        """
        scan = sp_keys(stranger_seed())[0]
        assert any("K_max" in case["comment"] for case in BIP352_SENDING)
        codes = [(scan, i.to_bytes(33, "big")) for i in range(silent_payments.K_MAX + 1)]
        with pytest.raises(ValueError, match="too many payments"):
            silent_payments.code_order(codes)
        silent_payments.code_order(codes[:-1])


class TestBip375Vectors:
    """
    BIP-375's own PSBT vectors, as bitcoin/bips publishes them. Their inputs belong to
    the vector generator rather than to a seed here, so what they prove is the
    derivation and the refusals, not this device completing them.
    """
    @pytest.mark.parametrize("entry", BIP375_VECTORS["valid"],
                             ids=lambda entry: entry["description"][:48])
    def test_valid_vectors_parse(self, entry):
        p = PSBT.parse(a2b_base64(entry["psbt"]))
        assert p.version == 2
        assert silent_payments.has_send_fields(p) or p.outputs

    @pytest.mark.parametrize("entry", [e for e in BIP375_VECTORS["valid"]
                                       if BIP375_SHARED_SCAN_KEY not in e["description"]],
                             ids=lambda entry: entry["description"][:48])
    def test_completed_vectors_match_our_derivation(self, entry):
        """
        Every script a completed vector carries must be the one this helper computes
        from that vector's own inputs, shares and codes.
        """
        p = PSBT.parse(a2b_base64(entry["psbt"]))
        recipients = [(i, out.unknown[b"\x09"]) for i, out in enumerate(p.outputs)
                      if b"\x09" in out.unknown]
        if not all(p.outputs[i].script_pubkey for i, _ in recipients):
            pytest.skip("not completed: the signer's part is still missing")

        eligible = [inp for inp in p.inputs if vector_input_key(inp)[0]]
        keys = [vector_input_key(inp)[1] for inp in eligible]
        if not eligible:
            pytest.skip("no input of one of BIP-352's four types, so there is no sum")
        if any(key is None for key in keys):
            pytest.skip("an eligible input states no public key")
        a_point = silent_payments._lincomb([(pub, 1) for pub in keys])
        outpoints = [bytes(inp.txid)[::-1] + inp.vout.to_bytes(4, "little") for inp in p.inputs]
        hash_of_inputs = silent_payments.input_hash(outpoints, a_point)

        def share_for(scan: bytes):
            whole = p.unknown.get(b"\x07" + scan)
            if whole:
                return ec.PublicKey.parse(whole)
            # Only an eligible input's share belongs in the sum, exactly as only its
            # key belongs in A.
            parts = [ec.PublicKey.parse(inp.unknown[b"\x1d" + scan]) for inp in eligible
                     if b"\x1d" + scan in inp.unknown]
            return silent_payments._lincomb([(part, 1) for part in parts])

        codes = [(info[:33], info[33:]) for _, info in recipients]
        for (index, info), k in zip(recipients, silent_payments.code_order(codes)):
            computed = silent_payments.output_script(
                share_for(info[:33]), ec.PublicKey.parse(info[33:]), hash_of_inputs, k)
            assert computed == p.outputs[index].script_pubkey.data

    @pytest.mark.parametrize("entry", BIP375_VECTORS["invalid"],
                             ids=lambda entry: entry["description"][:48])
    def test_invalid_vectors_are_refused(self, entry):
        with pytest.raises((InvalidPSBTError, ValueError)):
            PSBTParser(parse_kept(a2b_base64(entry["psbt"])), seed=abandon_seed(),
                       network=TESTNET)

    @pytest.mark.parametrize("fragment, match", [
        ("missing PSBT_OUT_SP_V0_INFO field when PSBT_OUT_SP_V0_LABEL", "label but no keys"),
        ("incorrect byte length for PSBT_OUT_SP_V0_INFO", "malformed Silent Payment field"),
        # These two vectors arrive signed, and being signed already is the first thing
        # wrong with them as a request to this device.
        ("incorrect byte length for PSBT_IN_SP_ECDH_SHARE", "already signed"),
        ("incorrect byte length for PSBT_IN_SP_DLEQ", "already signed"),
    ])
    def test_malformed_fields_are_refused_for_their_own_reason(self, fragment, match):
        """
        These are refused on their fields, before this seed's keys are read: a request
        this device cannot act on should say so, not report the wrong wallet.
        """
        entry = next(e for e in BIP375_VECTORS["invalid"] if fragment in e["description"])
        with pytest.raises(InvalidPSBTError, match=match) as e:
            PSBTParser(parse_kept(a2b_base64(entry["psbt"])), seed=abandon_seed(),
                       network=TESTNET)
        assert e.value.code == RejectCode.UNSUPPORTED_SILENT_PAYMENT

    def test_the_shared_scan_key_vector_disagrees_with_the_text(self):
        """
        Two codes sharing a scan key are the one case where BIP-375's text and its own
        vectors part company: the text sorts the codes to fix k, this vector assigns k
        by output index, and the scripts differ. This device follows the text, as
        Sparrow does, so its answer for this vector is the other one. If the vector or
        the text changes, this test is what says so.
        """
        entry = next(e for e in BIP375_VECTORS["valid"]
                     if BIP375_SHARED_SCAN_KEY in e["description"])
        p = PSBT.parse(a2b_base64(entry["psbt"]))
        recipients = [(i, out.unknown[b"\x09"]) for i, out in enumerate(p.outputs)
                      if b"\x09" in out.unknown]
        eligible = [inp for inp in p.inputs if vector_input_key(inp)[0]]
        a_point = silent_payments._lincomb([(vector_input_key(inp)[1], 1) for inp in eligible])
        outpoints = [bytes(inp.txid)[::-1] + inp.vout.to_bytes(4, "little") for inp in p.inputs]
        hash_of_inputs = silent_payments.input_hash(outpoints, a_point)
        codes = [(info[:33], info[33:]) for _, info in recipients]
        scan = codes[0][0]
        share = silent_payments._lincomb(
            [(ec.PublicKey.parse(inp.unknown[b"\x1d" + scan]), 1) for inp in eligible
             if b"\x1d" + scan in inp.unknown])

        def scripts(ks):
            return [silent_payments.output_script(share, ec.PublicKey.parse(spend),
                                                 hash_of_inputs, k)
                    for (_scan, spend), k in zip(codes, ks)]

        in_the_vector = [p.outputs[i].script_pubkey.data for i, _ in recipients]
        assert scripts(range(len(codes))) == in_the_vector
        assert scripts(silent_payments.code_order(codes)) != in_the_vector


def send_secrets(kind: str, raw: bytes) -> list:
    """Every secret a send derives: each input's key, and their sum a."""
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(ABANDON)))
    p = PSBT.parse(raw)
    keys = []
    for _inp in p.inputs:
        derived = root.derive(SEND_PATHS[kind]).key
        keys.append(derived.taproot_tweak(b"").secret if kind == "p2tr" else derived.secret)
    secrets = [key.hex() for key in keys]
    secrets.append(silent_payments.secret_sum(
        [silent_payments.even_y_secret(key) if kind == "p2tr" else key for key in keys]).hex())
    return secrets


def sp_send_request(tweak: int = 0x02, recipients: list = None, modifiable: int = 0x03,
                    sighash: int = None) -> bytes:
    """
    A request that pays a Silent Payment address out of a received Silent Payment
    coin: BIP-376 spend fields on the input, BIP-375 fields on the output.
    """
    recipients = recipients or [sp_keys(stranger_seed()) + (None,)]
    d = (b_spend() + tweak) % SECP_N
    spend_pub = ec.PrivateKey(b_spend().to_bytes(32, "big")).get_public_key().sec()
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(" ".join(ABANDON)))
    path = [0x80000000 + 352, 0x80000001, 0x80000000, 0x80000000, 0]
    spk = b"\x51\x20" + xonly_of(d)

    global_fields = {
        b"\x02": (2).to_bytes(4, "little"),
        b"\x04": compact.to_bytes(1),
        b"\x05": compact.to_bytes(len(recipients)),
        b"\xfb": (2).to_bytes(4, "little"),
        b"\x06": bytes([modifiable]),
    }
    fields = {
        b"\x01": (10_000).to_bytes(8, "little") + compact.to_bytes(len(spk)) + spk,
        b"\x0e": bytes([0xCD]) * 32,
        b"\x0f": (0).to_bytes(4, "little"),
        b"\x10": (0xFFFFFFFE).to_bytes(4, "little"),
        b"\x1f" + spend_pub: path_field(root.my_fingerprint, path),
        b"\x20": tweak.to_bytes(32, "big"),
    }
    if sighash is not None:
        fields[b"\x03"] = sighash.to_bytes(4, "little")
    raw = bytearray(b"psbt\xff") + write_map(global_fields) + write_map(fields)
    for scan, spend, label in recipients:
        out = {b"\x03": (9_000).to_bytes(8, "little"), b"\x09": scan + spend}
        if label is not None:
            out[b"\x0a"] = label.to_bytes(4, "little")
        raw += write_map(out)
    return bytes(raw)


def input_records(data: bytes, index: int = 1) -> list:
    """One map's records in order, so a repeated key is visible."""
    return [(key, value) for key, value, _s, _e in silent_payments._maps(data)[index][2]]


class TestSendRoundTwo:
    """The four defects the second review round found, each with its own case."""

    def test_an_explicit_sighash_all_is_not_written_twice(self):
        """
        A request may state SIGHASH_ALL itself. Writing our own alongside it makes a
        psbt with two PSBT_IN_SIGHASH_TYPE records, which no parser will read back.
        """
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)], sighash=0x01)
        p, _ = parsed_send(raw)
        silent_payments.sign_send_inputs(p, abandon_seed(), TESTNET)
        signed = silent_payments.psbt_bytes(p)

        assert [key for key, _ in input_records(signed)].count(b"\x03") == 1
        assert PSBT.parse(signed).inputs[0].sighash_type == 0x01
        assert undo_send_changes(signed, raw) == raw

    def test_a_send_from_a_received_silent_payment_coin(self):
        """
        Spending a Silent Payment coin to a Silent Payment address is one transaction,
        not two: the send's rules apply to it, not the spend-only ones (SIGHASH_ALL
        rather than DEFAULT, and flags this device is the one to clear).
        """
        raw = sp_send_request()
        p, parser = parsed_send(raw)
        assert parser.silent_payment_send
        assert all(parser.silent_payment_inputs)
        assert p.unknown[b"\x06"] == b"\x00"
        assert p.outputs[0].script_pubkey.data.startswith(b"\x51\x20")

        silent_payments.sign_send_inputs(p, abandon_seed(), TESTNET)
        signed = silent_payments.psbt_bytes(p)
        assert undo_send_changes(signed, raw) == raw
        signature = dict(input_records(signed))[b"\x13"]
        assert len(signature) == 65 and signature[64] == 0x01
        reparsed = PSBT.parse(signed)
        message = reparsed.sighash(0, sighash=SIGHASH.ALL)
        assert bip340_verify(reparsed.inputs[0].utxo.script_pubkey.data[2:], message,
                             signature[:64])

    def test_a_spend_still_needs_sighash_default(self):
        """The spend-only rules stay in force for a spend that pays no one silently."""
        p = sp_psbt("01-sp-spend-1in")
        p.inputs[0].sighash_type = 0x01
        assert_refused(p, RejectCode.UNSUPPORTED_SIGHASH, match="not SIGHASH_DEFAULT")

    def test_a_valid_supplied_dleq_proof_is_kept(self):
        """
        A proof that already holds is left alone. Replacing it with our own would be a
        change the export is right to refuse, and there is nothing to gain by it.
        """
        scan = sp_keys(stranger_seed())[0]
        raw = send_request("p2wpkh", [sp_keys(stranger_seed()) + (None,)])
        prepared, _ = parsed_send(raw)
        share, proof = prepared.unknown[b"\x07" + scan], prepared.unknown[b"\x08" + scan]

        maps = raw_maps(raw)
        maps[0][b"\x07" + scan] = share
        maps[0][b"\x08" + scan] = proof
        supplied = rebuild(maps)

        p, _ = parsed_send(supplied)
        assert p.unknown[b"\x08" + scan] == proof
        silent_payments.sign_send_inputs(p, abandon_seed(), TESTNET)
        signed = silent_payments.psbt_bytes(p)
        assert undo_send_changes(signed, supplied) == supplied
        assert dict(input_records(signed))[b"\x03"] == (1).to_bytes(4, "little")


class TestSharedScanKeyOrdering:
    """
    Two codes with one scan key is the case where BIP-375's text and its own published
    vectors part company: the text sorts the codes to fix k, the vectors go by output
    index. This device follows the text, and so does Sparrow -- drongo sorts each scan
    key's group by the serialized code -- which is what a wallet paying itself while
    its change shares that scan key depends on.
    """
    def test_k_follows_the_sorted_codes_not_the_output_order(self):
        scan, spend = sp_keys(stranger_seed())
        labeled = labeled_spend_key(stranger_seed(), 3)
        first, second = sorted([spend, labeled])
        raw = send_request("p2wpkh", [(scan, labeled, 3), (scan, spend, None)])
        p, parser = parsed_send(raw)

        a = bytes.fromhex(send_secrets("p2wpkh", raw)[-1])
        share = silent_payments.ecdh_share(a, ec.PublicKey.parse(scan))
        outpoints = [bytes(inp.txid)[::-1] + inp.vout.to_bytes(4, "little") for inp in p.inputs]
        hash_of_inputs = silent_payments.input_hash(outpoints, ec.PrivateKey(a).get_public_key())
        expected = {
            first: silent_payments.output_script(share, ec.PublicKey.parse(first), hash_of_inputs, 0),
            second: silent_payments.output_script(share, ec.PublicKey.parse(second), hash_of_inputs, 1),
        }
        assert p.outputs[0].script_pubkey.data == expected[labeled]
        assert p.outputs[1].script_pubkey.data == expected[spend]
        assert p.outputs[0].script_pubkey.data != p.outputs[1].script_pubkey.data
        assert [r["change"] for r in parser.silent_payment_recipients] == [False, False]

    def test_our_own_change_beside_a_payment_to_ourselves(self):
        """
        The Sparrow shape: a self-send to this wallet's own address with label-0 change
        back to it. Both codes share this seed's scan key, so this is the case the
        ordering decides, and the device has to sign it rather than refuse.
        """
        scan, spend = sp_keys()
        change_scan, change_spend = change_code()
        assert scan == change_scan
        raw = send_request("p2wpkh", [(scan, spend, None), (change_scan, change_spend, 0)])
        p, parser = parsed_send(raw)
        assert [r["change"] for r in parser.silent_payment_recipients] == [False, True]

        silent_payments.sign_send_inputs(p, abandon_seed(), TESTNET)
        signed = silent_payments.psbt_bytes(p)
        assert undo_send_changes(signed, raw) == raw
        assert PSBTParser.sig_count(PSBT.parse(signed)) == 1
