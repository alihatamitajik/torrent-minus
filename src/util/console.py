from rich.console import Console
from rich.highlighter import ISO8601Highlighter
import time


class LogConsole:
    """Simple console setup that will print requested logs in the console"""

    def __init__(self, handler, name="console") -> None:
        """Initialize

        Args:
            handler (function): gets a string and returns list of strings which
            are in log formats. console do a highlighting on it and prints the
            logs.
        """
        self.handle = handler
        self.name = name
        self.console = Console()
        self.date = ISO8601Highlighter()

    def start(self):
        while True:
            cmd = self.console.input(
                f"[bold yellow]{self.name}[/bold yellow] [cyan]❯[/cyan][purple]❯[/purple] ")
            if cmd == 'clear':
                self.console.clear()
            elif cmd == 'exit':
                exit(0)
            else:
                with self.console.status('Searching...'):
                    time.sleep(0.5)  # beautifying
                    for line in self.handle(cmd):
                        self.console.print(line)
