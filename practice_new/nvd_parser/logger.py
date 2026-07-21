from datetime import datetime


def log(message: str) -> None:
    """Вывод логов в реальном времени с принудительным сбросом буфера для Docker."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)
