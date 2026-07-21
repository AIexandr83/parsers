import glob
import json
import os
from typing import Optional

from config import settings
from dto import CVEDto
from logger import log


def parse_cve_file(file_path: str) -> Optional[CVEDto]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
        data = json.loads(raw_text)

        cve_id = data.get("cveMetadata", {}).get("cveId")
        if not cve_id:
            return None

        descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
        cvss_score = None
        for m in metrics:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                if key in m:
                    cvss_score = m[key].get("baseScore")
                    break
            if cvss_score is not None:
                break

        return CVEDto(
            cve_number=cve_id,
            description=(desc_text[:5000] if desc_text else "No description available"),
            cvss_score=cvss_score,
            raw_content=raw_text[:100000],
            source=settings.SOURCE_NAME,
        )
    except Exception as e:
        log(f"[Парсер Ошибка] Ошибка при разборе файла {file_path}: {e}")
        return None


def find_all_cve_files() -> list:
    search_path = os.path.join(settings.REPO_PATH, "cves", "**", "*.json")
    all_files = glob.glob(search_path, recursive=True)
    return [f for f in all_files if "delta" not in os.path.basename(f)]


def read_delta_log() -> list:
    delta_log_path = os.path.join(settings.REPO_PATH, "deltaLog.json")
    if not os.path.exists(delta_log_path):
        log("[Обновление] Файл deltaLog.json не обнаружен. Изменений нет.")
        return []

    try:
        with open(delta_log_path, "r", encoding="utf-8") as f:
            delta_data = json.load(f)

        if not delta_data or not isinstance(delta_data, list):
            log("[Обновление] deltaLog.json пуст или имеет неверный формат.")
            return []

        latest_commit_delta = delta_data[0]
        added = latest_commit_delta.get("vulnerabilitiesAdded", [])
        changed = latest_commit_delta.get("vulnerabilitiesChanged", [])

        total_updates = len(added) + len(changed)
        if total_updates == 0:
            log("[Обновление] Новых или изменённых уязвимостей в дельте не обнаружено.")
            return []

        log(f"[Обновление] Обнаружено изменений: {total_updates} (добавлено: {len(added)}, изменено: {len(changed)}).")

        files_to_parse = []
        for item in added + changed:
            rel_path = item.get("githubLink") or item.get("path")
            if not rel_path:
                continue
            if "blob/main/" in rel_path:
                rel_path = rel_path.split("blob/main/")[-1]
            full_path = os.path.join(settings.REPO_PATH, rel_path)
            if os.path.exists(full_path):
                files_to_parse.append(full_path)
        return files_to_parse
    except Exception as e:
        log(f"[Обновление Ошибка] Не удалось обработать deltaLog.json: {e}")
        return []