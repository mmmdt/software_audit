"""
cli.py — минимальный интерфейс командной строки для утилиты *software‑audit*.

Примеры
--------
    python -m software_audit.cli             # отчёт CSV + запись в БД
    python -m software_audit.cli --json      # отчёт JSON + запись в БД
    python software_audit/cli.py --csv --json

По умолчанию создаёт *report.csv* в рабочем каталоге.
"""

from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path
from typing import List, Dict


# поддерживаем запуск как пакетом (`python -m software_audit.cli`)
# и прямым файлом (`python software_audit/cli.py`)
try:
    from .scanner import scan, save_to_db, DB_PATH   # пакетный импорт
except ImportError:
    from scanner import scan, save_to_db, DB_PATH    # прямой запуск из каталога


# ---------- helpers ----------------------------------------------------------------
def _export_csv(rows: List[Dict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(rows[0].keys() if rows else ["name", "version", "vendor", "install_date", "host"])
        w.writerows([r.values() for r in rows])


def _export_json(rows: List[Dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


# ---------- entry‑point -------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(prog="software-audit", description="Сканер установленного ПО")
    p.add_argument("--csv", action="store_true", help="Сохранить отчёт в report.csv")
    p.add_argument("--json", action="store_true", help="Сохранить отчёт в report.json")
    args = p.parse_args()

    t0 = time.perf_counter()
    rows = scan()
    save_to_db(rows)
    dt = time.perf_counter() - t0

    if args.json:
        _export_json(rows, Path("report.json"))
    if args.csv or not args.json:
        _export_csv(rows, Path("report.csv"))

    print(f"✓ Найдено {len(rows)} пакетов; завершено за {dt:.1f} с; БД → {DB_PATH}")


if __name__ == "__main__":
    main()