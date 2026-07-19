import glob
import json
import os
import re
from typing import Iterator

from config import settings
from dto import ExploitDto
from logger import log

_CVE_FROM_FILENAME = re.compile(r"(CVE-\d{4}-\d+)")


def find_all_cve_files() -> list:
    search_path = os.path.join(settings.REPO_PATH, "*", "CVE-*.json")
    return glob.glob(search_path)


def parse_cve_file(file_path: str) -> Iterator[ExploitDto]:
    # Один файл = один CVE (по имени файла), но внутри — МАССИВ репозиториев/
    filename = os.path.basename(file_path)
    match = _CVE_FROM_FILENAME.search(filename)
    if not match:
        return
    cve_number = match.group(1)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            repos = json.load(f)
    except Exception as e:
        log(f"[Парсер Ошибка] Не удалось разобрать файл {file_path}: {e}")
        return

    if not isinstance(repos, list):
        return

    for repo in repos:
        exploit_id = repo.get("full_name")
        if not exploit_id:
            continue

        yield ExploitDto(
            exploit_id=exploit_id,
            cve_number=cve_number,
            title=repo.get("description") or repo.get("name"),
            url=repo.get("html_url"),
            published_date=repo.get("created_at"),
            raw_content=json.dumps(repo, ensure_ascii=False)[:20000],
            source=settings.SOURCE_NAME,
        )