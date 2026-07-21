import os
import zipfile

import requests
import urllib3

from config import settings
from logger import log

# bdu.fstec.ru использует ГОСТ-криптографию в цепочке сертификатов, которую
# стандартная сборка OpenSSL в контейнере не поддерживает (нет GOST engine).
# Поэтому для ЭТОГО конкретного запроса проверка TLS отключена осознанно —
# это известное техническое ограничение среды, а не ошибка/недосмотр.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def download_and_extract() -> str:
    os.makedirs(os.path.dirname(settings.DOWNLOAD_PATH), exist_ok=True)

    log("[Загрузка] Скачиваем vulxml.zip с bdu.fstec.ru...")
    log("[Загрузка] ВНИМАНИЕ: проверка TLS отключена (сайт использует ГОСТ-сертификаты, "
        "не поддерживаемые стандартным OpenSSL контейнера).")
    response = requests.get(settings.VULXML_URL, timeout=180, verify=False)
    response.raise_for_status()

    with open(settings.DOWNLOAD_PATH, "wb") as f:
        f.write(response.content)

    log("[Загрузка] Распаковываем архив...")
    os.makedirs(settings.EXTRACT_PATH, exist_ok=True)
    with zipfile.ZipFile(settings.DOWNLOAD_PATH, "r") as zf:
        zf.extractall(settings.EXTRACT_PATH)

    log(f"[Загрузка] Содержимое {settings.EXTRACT_PATH} после распаковки:")
    for root, _, files in os.walk(settings.EXTRACT_PATH):
        for name in files:
            log(f"    {os.path.join(root, name)}")

    export_file = _find_export_xml()
    log(f"[Загрузка] Используем файл: {export_file}")
    return export_file


def _find_export_xml() -> str:
    import glob

    candidates = glob.glob(os.path.join(settings.EXTRACT_PATH, "**", "*.xml"), recursive=True)
    if not candidates:
        raise FileNotFoundError(
            f"Не нашли ни одного .xml файла внутри {settings.EXTRACT_PATH}. "
            f"Проверь структуру архива вручную: docker exec -it bdu_parser sh"
        )
    return max(candidates, key=os.path.getsize)