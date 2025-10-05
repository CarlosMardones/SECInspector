import logging


class Logger:
    """Wrapper del sistema estándar de logging de Python.

    - Mantiene compatibilidad con log(message) -> nivel INFO.
    - Expone métodos info/warning/error/debug.
    - Permite configurar nombre, nivel y salida opcional a archivo.
    """

    def __init__(self, name: str = "SECInspector", level: int = logging.INFO, log_to_file: str | None = None):
        self.logger = logging.getLogger(name)

        if not self.logger.handlers:
            self.logger.setLevel(level)
            self.logger.propagate = False

            formatter = logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            self.logger.addHandler(stream_handler)

            if log_to_file:
                file_handler = logging.FileHandler(log_to_file, encoding="utf-8")
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

    def set_level(self, level: int) -> None:
        self.logger.setLevel(level)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def info(self, message: str) -> None:
        self.logger.info(message)

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def error(self, message: str) -> None:
        self.logger.error(message)

    def debug(self, message: str) -> None:
        self.logger.debug(message)