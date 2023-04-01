import threading
from functools import wraps


def threaded(fn):
    """Threaded decorator

    This decorator will run a function or method in a new thread
    """
    def run(*args, **kwargs):
        t = threading.Thread(target=fn, daemon=True, args=args, kwargs=kwargs)
        t.start()
        return t
    return run
