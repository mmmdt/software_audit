"""
scanner.py — кроссплатформовый сбор сведений об установленном ПО.

Поддерживаемые платформы
------------------------
* Windows 10/11   — Win32‑реестр + winget
* Debian/Ubuntu   — dpkg‑query, snap, flatpak
* RHEL‑like       — rpm
* macOS           — system_profiler (+ Homebrew, если установлен)

Скрипт ничего не устанавливает, работает офлайн и сохраняет данные
в SQLite‑файл software_audit.sqlite (режим WAL).
"""

from __future__ import annotations

import json
import platform
import shlex
import shutil
import socket
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterable, List, Dict

DB_PATH = Path(__file__).with_suffix(".sqlite")


# --------------------------------------------------------------------------- helpers
def _run(cmd: str) -> str:
    """Run shell command and return UTF‑8 stdout (errors suppressed)."""
    return subprocess.run(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf‑8",
        check=False,
    ).stdout


def _host() -> str:
    return socket.gethostname()


# --------------------------------------------------------------------------- Windows
def _parse_win_reg() -> List[Dict]:
    """MSI‑установщики из веток Uninstall."""
    try:
        import winreg  # type: ignore  # noqa: WPS433
    except ModuleNotFoundError:
        return []

    rows: List[Dict] = []
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    def _val(k, name):
        try:
            return winreg.QueryValueEx(k, name)[0]
        except OSError:
            return ""

    for root, path in hives:
        try:
            with winreg.OpenKey(root, path) as root_key:
                for i in range(winreg.QueryInfoKey(root_key)[0]):
                    try:
                        subkey = winreg.EnumKey(root_key, i)
                        with winreg.OpenKey(root_key, subkey) as k:
                            disp_name = _val(k, "DisplayName")
                            if not disp_name:
                                continue
                            rows.append(
                                {
                                    "name": disp_name,
                                    "version": _val(k, "DisplayVersion"),
                                    "vendor": _val(k, "Publisher"),
                                    "install_date": _val(k, "InstallDate"),
                                    "host": _host(),
                                }
                            )
                    except OSError:
                        continue
        except OSError:
            continue
    return rows


def _parse_winget() -> List[Dict]:
    if not shutil.which("winget"):
        return []
    out = _run("winget list --source winget --output json")
    try:
        packages = json.loads(out).get("InstalledPackages", [])
    except json.JSONDecodeError:
        return []
    return [
        {
            "name": p.get("Name"),
            "version": p.get("Version"),
            "vendor": p.get("Publisher"),
            "install_date": "",
            "host": _host(),
        }
        for p in packages
    ]


# --------------------------------------------------------------------------- Linux
def _parse_dpkg() -> List[Dict]:
    if shutil.which("dpkg-query") is None:
        return []
    out = _run("dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n'")
    rows = []
    for line in out.strip().splitlines():
        pkg, ver, vendor = line.split("\t")
        rows.append(
            {"name": pkg, "version": ver, "vendor": vendor, "install_date": "", "host": _host()}
        )
    return rows


def _parse_rpm() -> List[Dict]:
    if shutil.which("rpm") is None:
        return []
    out = _run("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\n'")
    rows = []
    for line in out.splitlines():
        pkg, ver, vendor = line.split("\t")
        rows.append(
            {"name": pkg, "version": ver, "vendor": vendor, "install_date": "", "host": _host()}
        )
    return rows


def _parse_snap_flatpak() -> List[Dict]:
    rows: List[Dict] = []
    if shutil.which("snap"):
        for ln in _run("snap list").splitlines()[1:]:
            parts = ln.split()
            if len(parts) >= 2:
                rows.append(
                    {
                        "name": parts[0],
                        "version": parts[1],
                        "vendor": "snap",
                        "install_date": "",
                        "host": _host(),
                    }
                )
    if shutil.which("flatpak"):
        for ln in _run("flatpak list --app --columns=application,version,origin").splitlines():
            app, ver, origin = ln.split("\t")
            rows.append(
                {
                    "name": app,
                    "version": ver,
                    "vendor": origin,
                    "install_date": "",
                    "host": _host(),
                }
            )
    return rows


# --------------------------------------------------------------------------- macOS
def _parse_macos() -> List[Dict]:
    if platform.system() != "Darwin":
        return []
    rows: List[Dict] = []
    sp_json = _run("system_profiler SPApplicationsDataType -json")
    try:
        apps = json.loads(sp_json).get("SPApplicationsDataType", [])
    except json.JSONDecodeError:
        apps = []
    for app in apps:
        rows.append(
            {
                "name": app.get("_name", ""),
                "version": app.get("version", ""),
                "vendor": app.get("obtained_from", ""),
                "install_date": "",
                "host": _host(),
            }
        )
    if shutil.which("brew"):
        for ln in _run("brew list --versions").splitlines():
            parts = ln.split()
            if len(parts) >= 2:
                rows.append(
                    {
                        "name": parts[0],
                        "version": parts[1],
                        "vendor": "Homebrew",
                        "install_date": "",
                        "host": _host(),
                    }
                )
    return rows


# --------------------------------------------------------------------------- public
def scan() -> List[Dict]:
    """Return list of detected packages for current OS."""
    os_name = platform.system()
    pkgs: List[Dict] = []

    if os_name == "Windows":
        pkgs += _parse_win_reg()
        pkgs += _parse_winget()
    elif os_name == "Darwin":
        pkgs += _parse_macos()
    else:  # Linux/*nix
        pkgs += _parse_dpkg()
        pkgs += _parse_rpm()
        pkgs += _parse_snap_flatpak()

    return pkgs


def save_to_db(rows: Iterable[Dict]) -> None:
    """Rewrite table *packages* with fresh scan results."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS packages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            version TEXT,
            vendor TEXT,
            install_date TEXT,
            host TEXT
        )
        """
    )
    cur.execute("DELETE FROM packages")
    cur.executemany(
        "INSERT INTO packages(name, version, vendor, install_date, host) "
        "VALUES(:name, :version, :vendor, :install_date, :host)",
        rows,
    )
    con.commit()
    con.close()