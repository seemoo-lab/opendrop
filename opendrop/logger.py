import colorama
import logging

class Logging:
    def info(message: str) -> None:
        logging.info(message)
        print(f"{colorama.Fore.BLUE}{colorama.Style.BRIGHT}[INFO]{colorama.Style.RESET_ALL} {message}")
    def error(message: str) -> None:
        logging.error(message)
        print(f"{colorama.Fore.RED}{colorama.Style.BRIGHT}[ERROR]{colorama.Style.RESET_ALL} {message}")
    def success(message: str) -> None:
        print(f"{colorama.Fore.GREEN}{colorama.Style.BRIGHT}[SUCCESS]{colorama.Style.RESET_ALL} {message}")
    def warning(message: str) -> None:
        logging.warning(message)
        print(f"{colorama.Fore.YELLOW}{colorama.Style.BRIGHT}[WARNING]{colorama.Style.RESET_ALL} {message}")
    def debug(message: str) -> None:
        logging.debug(message)
        print(f"{colorama.Fore.MAGENTA}{colorama.Style.BRIGHT}[DEBUG]{colorama.Style.RESET_ALL} {message}")
