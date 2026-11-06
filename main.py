import asyncio
import json
import os
import time
from typing import Any

import decky


DEFAULT_FOV = 0.75
MIN_FOV = 0.5
MAX_FOV = 1.5
READY_AGE_SECONDS = 45
RATE_LIMIT_SECONDS = 1.0
GAME_PROCESS_NAME = "DarkSoulsRemast"
PATCHER_PROCESS_NAME = "dsr-fov-patcher"
SETTINGS_FILE = "settings.json"


class Plugin:
    def __init__(self) -> None:
        self.fov = DEFAULT_FOV
        self.last_error = ""
        self.last_message = "Ready."
        self.last_applied_pid: int | None = None
        self.last_applied_fov: float | None = None
        self.last_patcher_started_at = 0.0
        self.pending_action: dict[str, Any] | None = None
        self.process_lock = asyncio.Lock()
        self.runner_task: asyncio.Task[None] | None = None
        self.monitor_task: asyncio.Task[None] | None = None

    async def _main(self) -> None:
        os.makedirs(decky.DECKY_PLUGIN_SETTINGS_DIR, exist_ok=True)
        self._load_settings()
        self.monitor_task = asyncio.create_task(self._monitor_game())
        decky.logger.info("Dark Souls Remastered FOV plugin loaded.")

    async def _unload(self) -> None:
        for task in (self.runner_task, self.monitor_task):
            if task and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (self.runner_task, self.monitor_task) if task),
            return_exceptions=True,
        )
        decky.logger.info("Dark Souls Remastered FOV plugin unloaded.")

    async def _uninstall(self) -> None:
        decky.logger.info("Dark Souls Remastered FOV plugin uninstalled.")

    async def get_state(self) -> dict[str, Any]:
        return await self._state()

    async def set_fov(self, fov: float) -> dict[str, Any]:
        self.fov = self._validate_fov(fov)
        self._save_settings()
        self.pending_action = {"kind": "set", "fov": self.fov}
        self.last_message = f"Saved FOV {self.fov:.2f}."
        self._ensure_runner()
        return await self._state()

    async def reset_fov(self) -> dict[str, Any]:
        self.fov = DEFAULT_FOV
        self._save_settings()
        self.pending_action = {"kind": "restore"}
        self.last_message = "Saved default FOV."
        self._ensure_runner()
        return await self._state()

    def _settings_path(self) -> str:
        return os.path.join(decky.DECKY_PLUGIN_SETTINGS_DIR, SETTINGS_FILE)

    def _load_settings(self) -> None:
        try:
            with open(self._settings_path(), "r", encoding="utf-8") as settings_file:
                data = json.load(settings_file)
            self.fov = self._validate_fov(float(data.get("fov", DEFAULT_FOV)))
        except FileNotFoundError:
            self._save_settings()
        except Exception as error:
            self.fov = DEFAULT_FOV
            self.last_error = f"Could not load settings: {error}"
            decky.logger.exception("Failed to load settings.")

    def _save_settings(self) -> None:
        tmp_path = f"{self._settings_path()}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as settings_file:
            json.dump({"fov": self.fov}, settings_file)
        os.replace(tmp_path, self._settings_path())

    def _validate_fov(self, fov: float) -> float:
        if fov < MIN_FOV or fov > MAX_FOV:
            raise ValueError(f"FOV must be between {MIN_FOV:.2f} and {MAX_FOV:.2f}.")
        return round(float(fov), 3)

    def _ensure_runner(self) -> None:
        if not self.runner_task or self.runner_task.done():
            self.runner_task = asyncio.create_task(self._drain_pending_actions())

    async def _monitor_game(self) -> None:
        while True:
            try:
                status = await self._game_status()
                if not status["running"]:
                    self.last_applied_pid = None
                    self.last_applied_fov = None
                elif (
                    status["ready"]
                    and self.fov != DEFAULT_FOV
                    and self.pending_action is None
                    and (
                        self.last_applied_pid != status["pid"]
                        or self.last_applied_fov != self.fov
                    )
                ):
                    self.pending_action = {"kind": "set", "fov": self.fov}
                    self._ensure_runner()
            except asyncio.CancelledError:
                raise
            except Exception:
                decky.logger.exception("Game monitor failed.")
            await asyncio.sleep(10)

    async def _drain_pending_actions(self) -> None:
        while self.pending_action is not None:
            action = self.pending_action
            self.pending_action = None

            delay = await self._delay_before_patching()
            if delay is None:
                if action["kind"] == "restore":
                    self.last_message = "Game is not running; default FOV is saved."
                else:
                    self.last_message = f"Game is not running; FOV {action['fov']:.2f} is saved."
                continue

            if delay > 0:
                if self.pending_action is None:
                    self.pending_action = action
                await asyncio.sleep(min(delay, 5))
                continue

            async with self.process_lock:
                if self.pending_action is not None:
                    continue

                status = await self._game_status()
                if not status["running"]:
                    self.last_message = "Game stopped before the patcher could run."
                    continue
                if status["pid"] is None:
                    self.pending_action = action
                    self.last_message = "Multiple game processes found; waiting for one target."
                    await asyncio.sleep(5)
                    continue
                if not status["ready"]:
                    self.pending_action = action
                    await asyncio.sleep(min(status["wait_seconds"], 5))
                    continue

                since_last = time.monotonic() - self.last_patcher_started_at
                if since_last < RATE_LIMIT_SECONDS:
                    self.pending_action = action
                    await asyncio.sleep(RATE_LIMIT_SECONDS - since_last)
                    continue

                if await self._patcher_already_running():
                    self.pending_action = action
                    self.last_message = "Waiting for another FOV patcher process to finish."
                    await asyncio.sleep(1)
                    continue

                await self._run_patcher(status["pid"], action)

    async def _delay_before_patching(self) -> float | None:
        status = await self._game_status()
        if not status["running"]:
            return None
        if status["pid"] is None:
            self.last_message = "Multiple game processes found; waiting for one target."
            return 5
        if not status["ready"]:
            self.last_message = (
                "Dark Souls Remastered is still starting; "
                f"waiting {status['wait_seconds']}s before patching."
            )
            return float(status["wait_seconds"])
        since_last = time.monotonic() - self.last_patcher_started_at
        return max(0.0, RATE_LIMIT_SECONDS - since_last)

    async def _game_status(self) -> dict[str, Any]:
        pids = await self._pidof(GAME_PROCESS_NAME)

        if not pids:
            return {
                "running": False,
                "pid": None,
                "age_seconds": 0,
                "ready": False,
                "wait_seconds": 0,
                "status": "not_running",
            }

        if len(pids) > 1:
            return {
                "running": True,
                "pid": None,
                "age_seconds": 0,
                "ready": False,
                "wait_seconds": 0,
                "status": "multiple_processes",
            }

        pid = pids[0]
        age_seconds = self._process_age_seconds(pid)
        wait_seconds = max(0, READY_AGE_SECONDS - age_seconds)
        return {
            "running": True,
            "pid": pid,
            "age_seconds": age_seconds,
            "ready": wait_seconds == 0,
            "wait_seconds": wait_seconds,
            "status": "ready" if wait_seconds == 0 else "warming_up",
        }

    async def _pidof(self, name: str) -> list[int]:
        try:
            process = await asyncio.create_subprocess_exec(
                "pidof",
                name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await process.communicate()
        except FileNotFoundError:
            return []

        if process.returncode != 0:
            return []

        pids: list[int] = []
        for value in stdout.decode("utf-8", errors="replace").split():
            try:
                pids.append(int(value))
            except ValueError:
                pass
        return pids

    def _process_age_seconds(self, pid: int) -> int:
        try:
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as stat_file:
                stat = stat_file.read()
            after_comm = stat.rsplit(") ", 1)[1]
            start_time_ticks = int(after_comm.split()[19])
            clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
            with open("/proc/uptime", "r", encoding="utf-8") as uptime_file:
                uptime = float(uptime_file.read().split()[0])
            return max(0, int(uptime - (start_time_ticks / clock_ticks)))
        except Exception:
            return 0

    async def _patcher_already_running(self) -> bool:
        return bool(await self._pidof(PATCHER_PROCESS_NAME))

    def _patcher_path(self) -> str:
        candidates = [
            os.path.join(decky.DECKY_PLUGIN_DIR, "bin", PATCHER_PROCESS_NAME),
            os.path.join(decky.DECKY_PLUGIN_DIR, "backend", "out", PATCHER_PROCESS_NAME),
            os.path.join(os.getcwd(), "backend", "out", PATCHER_PROCESS_NAME),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return candidates[0]

    async def _run_patcher(self, pid: int, action: dict[str, Any]) -> None:
        patcher = self._patcher_path()
        if not os.path.isfile(patcher):
            self.last_error = f"FOV patcher was not found at {patcher}."
            self.last_message = self.last_error
            return

        args = [patcher, "--pid", str(pid)]
        if action["kind"] == "restore":
            args.append("--restore")
        else:
            args.append(f"{action['fov']:.3f}")

        self.last_patcher_started_at = time.monotonic()
        decky.logger.info("Running FOV patcher: %s", " ".join(args))

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            self.last_error = "FOV patcher timed out."
            self.last_message = self.last_error
            return
        except Exception as error:
            self.last_error = f"Could not start FOV patcher: {error}"
            self.last_message = self.last_error
            return

        output = stdout.decode("utf-8", errors="replace").strip()
        error_output = stderr.decode("utf-8", errors="replace").strip()

        if process.returncode == 0:
            self.last_error = ""
            self.last_applied_pid = pid
            if action["kind"] == "restore":
                self.last_applied_fov = DEFAULT_FOV
                self.last_message = "Restored default FOV."
            else:
                self.last_applied_fov = action["fov"]
                self.last_message = f"Applied FOV {action['fov']:.2f}."
            if output:
                decky.logger.info(output)
        else:
            self.last_error = error_output or output or "FOV patcher failed."
            self.last_message = self.last_error
            decky.logger.error("FOV patcher failed: %s", self.last_error)

    async def _state(self) -> dict[str, Any]:
        status = await self._game_status()
        message = self.last_message
        if status["status"] == "not_running":
            if self.fov == DEFAULT_FOV:
                message = "Dark Souls Remastered is not running; default FOV is saved."
            else:
                message = (
                    "Dark Souls Remastered is not running; "
                    f"FOV {self.fov:.2f} is saved."
                )
        elif status["status"] == "multiple_processes":
            message = "Multiple Dark Souls Remastered processes were found."
        elif status["status"] == "warming_up":
            message = f"Game detected; patching unlocks in {status['wait_seconds']}s."

        return {
            "fov": self.fov,
            "default_fov": DEFAULT_FOV,
            "min_fov": MIN_FOV,
            "max_fov": MAX_FOV,
            "step": 0.05,
            "game_running": status["running"],
            "game_ready": status["ready"],
            "pid": status["pid"],
            "age_seconds": status["age_seconds"],
            "wait_seconds": status["wait_seconds"],
            "busy": self.process_lock.locked()
            or (self.runner_task is not None and not self.runner_task.done()),
            "pending": self.pending_action is not None,
            "message": message,
            "error": self.last_error,
        }
