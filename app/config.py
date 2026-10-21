# ============================================================
# app/config.py — Application Configuration
# ============================================================
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # MongoDB
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_database: str = "sensitive_data_detection"

    # JWT
    secret_key: str = "change-this-secret-key"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440

    # App
    app_env: str = "development"
    upload_dir: str = "uploads"
    max_upload_size_mb: int = 20

    # Tesseract (optional)
    tesseract_cmd: str = ""

    # External AI (disabled by default)
    openai_api_key: str = ""
    external_ai_enabled: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

    @property
    def effective_tesseract_cmd(self) -> str:
        import os, shutil
        if self.tesseract_cmd and os.path.isfile(self.tesseract_cmd):
            return self.tesseract_cmd
        candidates = [
            os.path.expanduser(r"~\Tesseract-OCR\tesseract.exe"),
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
            shutil.which("tesseract") or "",
        ]
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return self.tesseract_cmd or ""

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def allowed_extensions(self) -> list[str]:
        return ["pdf", "docx", "txt", "png", "jpg", "jpeg"]

    @property
    def allowed_mime_types(self) -> list[str]:
        return [
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "text/plain",
            "image/png",
            "image/jpeg",
        ]


@lru_cache()
def get_settings() -> Settings:
    return Settings()
