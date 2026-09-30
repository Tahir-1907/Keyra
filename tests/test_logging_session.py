import io
import logging
import sys
import time
import unittest
from unittest import mock

from app.core import session as session_module
from app.core.session import AUTO_LOCK_CHOICES_SECONDS, SessionManager
from app.core.vault import Vault
from app.utils.logging import RedactingFilter
from tests.test_entries import MASTER, EntryTestCase


class TestRedactingFilter(unittest.TestCase):
    def setUp(self):
        self.stream = io.StringIO()
        self.errors = io.StringIO()
        self.logger = logging.getLogger(f"test-redact-{id(self)}")
        self.logger.propagate = False
        handler = logging.StreamHandler(self.stream)
        handler.addFilter(RedactingFilter())
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self._old_raise = logging.raiseExceptions

    def output(self) -> str:
        return self.stream.getvalue()

    def test_secret_in_arguments_is_redacted_and_never_printed(self):
        import contextlib

        with contextlib.redirect_stderr(self.errors):
            self.logger.info("password=%s", "SECRET-ARG")
            self.logger.info("token: %s fin", "SECRET-2")
            self.logger.info("connexion %s", "master_password=SECRET-3")
            self.logger.info("gabarit cassé %s %s", "SECRET-4")
        everything = self.output() + self.errors.getvalue()
        for secret in ("SECRET-ARG", "SECRET-2", "SECRET-3", "SECRET-4"):
            self.assertNotIn(secret, everything)
        self.assertEqual(self.errors.getvalue(), "")  # no more formatting error
        self.assertIn("password=[REDACTED]", self.output())

    def test_normal_messages_untouched(self):
        self.logger.info("Entry created: id=%d", 42)
        self.logger.info("Vault unlocked: %s", "personnel-3bde8c")
        self.assertEqual(self.output().splitlines(),
                         ["Entry created: id=42", "Vault unlocked: personnel-3bde8c"])


class TestSessionManager(EntryTestCase):
    def test_lock_if_idle(self):
        session = SessionManager(self.vault, auto_lock_seconds=60)
        self.assertFalse(session.lock_if_idle())
        session._last_activity -= 61
        self.assertTrue(session.should_lock())
        self.assertTrue(session.lock_if_idle())
        self.assertTrue(self.vault.is_locked)
        self.assertFalse(session.should_lock())  # already locked

    def test_touch_postpones(self):
        session = SessionManager(self.vault, auto_lock_seconds=60)
        session._last_activity -= 59
        session.touch()
        self.assertLess(session.idle_seconds(), 1)
        self.assertFalse(session.lock_if_idle())

    def test_never(self):
        session = SessionManager(self.vault, auto_lock_seconds=None)
        session._last_activity -= 10**6
        self.assertFalse(session.lock_if_idle())
        self.assertIn(None, AUTO_LOCK_CHOICES_SECONDS.values())

    def test_lock_now_wipes_key(self):
        session = SessionManager(self.vault)
        dek = self.vault._dek
        session.lock_now()
        self.assertTrue(self.vault.is_locked)
        self.assertEqual(bytes(dek), bytes(len(dek)))  # effacement best-effort
        self.vault.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)


class TestIdleClock(EntryTestCase):
    """Inactivity clock: the time spent asleep must count (CLOCK_BOOTTIME)."""

    def test_idle_time_includes_sleep(self):
        # Simulated clock that, like CLOCK_BOOTTIME, moves forward during sleep.
        now = [1000.0]
        session = SessionManager(self.vault, auto_lock_seconds=5 * 60, clock=lambda: now[0])
        now[0] += 60
        self.assertFalse(session.should_lock())
        now[0] += 8 * 3600  # a night asleep
        self.assertTrue(session.should_lock())
        self.assertTrue(session.lock_if_idle())

    @unittest.skipUnless(sys.platform.startswith("linux"), "CLOCK_BOOTTIME : Linux")
    def test_linux_uses_boottime(self):
        self.assertEqual(session_module.CLOCK_NAME, "CLOCK_BOOTTIME")

    def test_default_clock_is_monotonic_non_decreasing(self):
        session = SessionManager(self.vault)
        first = session.idle_seconds()
        self.assertGreaterEqual(first, 0)
        self.assertGreaterEqual(session.idle_seconds(), first)

    def test_fallback_when_boottime_does_not_exist(self):
        with mock.patch.object(session_module.time, "CLOCK_BOOTTIME", None, create=True):
            name, clock = session_module._select_clock()
        self.assertEqual(name, "monotonic")
        self.assertIs(clock, time.monotonic)

    def test_fallback_when_boottime_is_refused(self):
        with mock.patch.object(session_module.time, "CLOCK_BOOTTIME", 7, create=True), \
                mock.patch.object(session_module.time, "clock_gettime",
                                  side_effect=OSError("EINVAL")):
            name, clock = session_module._select_clock()
        self.assertEqual(name, "monotonic")
        self.assertIs(clock, time.monotonic)
