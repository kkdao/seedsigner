from seedsigner.helpers import qr as qr_module
from seedsigner.helpers.qr import QR


def test_fallback_keeps_the_qr_brightness(monkeypatch):
    """
    Without the qrencode binary (the Luckfox image has none), qrimage_io()
    falls back to the Python encoder. It must still draw the background the
    QR screen asked for, or the brightness keys do nothing.
    """
    def no_qrencode(cmd):
        raise FileNotFoundError("qrencode")

    monkeypatch.setattr(qr_module.subprocess, "call", no_qrencode)

    image = QR().qrimage_io("brightness", 240, 240, border=2, background_color="f8f8f8")

    # The top-left corner is quiet zone: background, never a module.
    assert image.getpixel((0, 0))[:3] == (0xf8, 0xf8, 0xf8)
