"""
Test-build diagnostics only, never for a pull request: every few seconds,
append free memory, this process's size and the current View to /userdata,
and keep the kernel's last messages there, each flushed to flash, so the
reason for a sudden reset can be read back from the board afterwards.
"""
import os
import subprocess
import threading
import time

LOG = "/userdata/diag.log"
DMESG = "/userdata/diag-dmesg.log"
INTERVAL = 5


def _write(path, text, mode):
    with open(path, mode) as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def _sample():
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, value = line.split(":", 1)
            mem[key] = value.split()[0]
    status = {}
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith(("VmRSS", "VmHWM", "Threads")):
                key, value = line.split(":", 1)
                status[key] = value.split()[0]
    with open("/proc/uptime") as f:
        uptime = f.read().split()[0]
    try:
        from seedsigner.controller import Controller
        stack = Controller.get_instance().back_stack
        view = type(stack[-1].view).__name__ if stack and getattr(stack[-1], "view", None) else "-"
    except Exception:
        view = "?"
    return (
        f"up={uptime} avail={mem.get('MemAvailable')} free={mem.get('MemFree')} "
        f"rss={status.get('VmRSS')} hwm={status.get('VmHWM')} threads={status.get('Threads')} view={view}\n"
    )


def _run():
    _write(LOG, f"===== app start pid={os.getpid()} =====\n", "a")
    while True:
        try:
            _write(LOG, _sample(), "a")
            out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
            _write(DMESG, "\n".join(out.splitlines()[-60:]) + "\n", "w")
        except Exception as e:
            try:
                _write(LOG, f"diag error: {e!r}\n", "a")
            except Exception:
                pass
        time.sleep(INTERVAL)


def start():
    if not os.path.isdir("/userdata"):
        return
    threading.Thread(target=_run, name="DiagRecorder", daemon=True).start()
