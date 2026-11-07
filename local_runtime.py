"""Own and recycle the local inference process; never terminate unrelated processes."""

import ctypes, os, pathlib, subprocess, time, urllib.request, json

ROOT = pathlib.Path(__file__).parent


def resident_bytes(pid):
    if os.name == "nt":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (n, ctypes.c_size_t)
                for n in [
                    "PeakWorkingSetSize",
                    "WorkingSetSize",
                    "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage",
                    "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage",
                    "PagefileUsage",
                    "PeakPagefileUsage",
                ]
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Counters),
            wintypes.DWORD,
        ]
        h = kernel.OpenProcess(0x410, False, pid)
        if not h:
            raise OSError("Cannot measure process memory")
        try:
            c = Counters()
            c.cb = ctypes.sizeof(c)
            if not psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb):
                raise OSError("Cannot read process memory")
            return max(c.WorkingSetSize, c.PeakWorkingSetSize)
        finally:
            kernel.CloseHandle(h)
    return int(pathlib.Path(f"/proc/{pid}/statm").read_text().split()[1]) * os.sysconf(
        "SC_PAGE_SIZE"
    )


class LocalRuntime:
    def __init__(self):
        self.process = None
        self.calls = 0
        self.restarts = 0
        self.max_observed = 0
        self.log = None

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.log:
            self.log.close()
            self.log = None

    def start(self):
        exe = (
            ROOT
            / "runtime"
            / ("llama-server.exe" if os.name == "nt" else "llama-server")
        )
        model = ROOT / "models" / "model-2b.gguf"
        if not exe.exists() or not model.exists():
            raise RuntimeError("Run python setup_local.py before starting the app")
        self.log = (ROOT / "data" / "managed-model.log").open("ab")
        self.process = subprocess.Popen(
            [
                str(exe),
                "-m",
                str(model),
                "-c",
                "2048",
                "-t",
                "2",
                "-tb",
                "2",
                "-np",
                "1",
                "-ngl",
                "0",
                "--host",
                "127.0.0.1",
                "--port",
                "8081",
                "--jinja",
            ],
            stdout=self.log,
            stderr=self.log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self.calls = 0
        for _ in range(120):
            if self.process.poll() is not None:
                raise RuntimeError("Model exited; inspect data/managed-model.log")
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:8081/health", timeout=1
                ) as r:
                    if r.status == 200:
                        return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("Model startup timeout")

    def ensure_ready(self):
        if not self.process or self.process.poll() is not None:
            self.start()
        used = resident_bytes(self.process.pid) + resident_bytes(os.getpid())
        self.max_observed = max(self.max_observed, used)
        # Recycling every six calls also bounds growth before the measured guard is reached.
        if used > 2_600_000_000 or self.calls >= 6:
            self.stop()
            self.restarts += 1
            self.start()

    def completed(self):
        self.calls += 1
        used = resident_bytes(self.process.pid) + resident_bytes(os.getpid())
        self.max_observed = max(self.max_observed, used)
        if used > 3_200_000_000:
            self.stop()

    def stats(self):
        return {
            "model_restarts": self.restarts,
            "max_observed_combined_resident_bytes": self.max_observed,
            "recycle_after_calls": 6,
            "memory_recycle_threshold_bytes": 2600000000,
            "measurement": "Sum of model and backend process high-water working sets observed across managed process lifetimes. OS overhead is not included; this is not an isolated-machine certification.",
        }
