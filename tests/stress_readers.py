"""Offline repetition of the reported regressions with a CPU-burning process."""
from contextlib import redirect_stdout
import io
import multiprocessing
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_routes_page import MirrorRegressions


def burn(started, stop):
    started.set()
    value = 1
    while not stop.is_set():
        for _ in range(10000):
            value = (value * 1664525 + 1013904223) & 0xffffffff


def main():
    context = multiprocessing.get_context('spawn')
    started, stop = context.Event(), context.Event()
    worker = context.Process(target=burn, args=(started, stop))
    worker.start()
    failures = 0
    try:
        if not started.wait(5):
            raise RuntimeError('CPU burner did not start')
        for name in ('test_combined_polling_under_concurrent_event_writer',
                     'test_publishers_and_readers_observe_one_transaction'):
            passed = 0
            for _ in range(50):
                result = unittest.TestResult()
                with redirect_stdout(io.StringIO()):
                    MirrorRegressions(name).run(result)
                if result.wasSuccessful():
                    passed += 1
                else:
                    for _, detail in result.errors + result.failures:
                        print(detail, file=sys.stderr)
            failures += 50 - passed
            print(f'CPU LOAD | MirrorRegressions.{name} | {passed}/50 passed', flush=True)
        if not worker.is_alive():
            raise RuntimeError('CPU burner exited before completion')
    finally:
        stop.set()
        worker.join(5)
        if worker.is_alive():
            worker.terminate()
            worker.join()
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
