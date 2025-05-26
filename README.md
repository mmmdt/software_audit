# software-audit

Минимальный офлайн-сканер установленного ПО  
(Windows 10/11, Ubuntu/Debian, RHEL/CentOS).  
Без серверов, без агентов, одна зависимость.

## Установка и запуск

```bash
python -m pip install -r requirements.txt          # установить psutil
python software_audit/cli.py                       # CSV + SQLite
python software_audit/cli.py --json                # JSON + SQLite
pyinstaller --onefile software_audit/cli.py        # собрать бинарник