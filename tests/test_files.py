"""Écriture privée et atomique (app.utils.files.write_private_atomic)."""

import os
import secrets
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.utils import files
from app.utils.files import write_private_atomic


class TestWritePrivateAtomic(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "fichier.bin"
        # umask permissif : les permissions ne doivent pas en dépendre.
        self._old_umask = os.umask(0o022)

    def tearDown(self):
        os.umask(self._old_umask)
        self._tmp.cleanup()

    def _mode(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def _leftovers(self) -> list[str]:
        return sorted(p.name for p in self.dir.iterdir() if p.name != self.path.name)

    def test_exact_content_and_private_permissions(self):
        data = secrets.token_bytes(4096)
        write_private_atomic(self.path, data)
        self.assertEqual(self.path.read_bytes(), data)
        self.assertEqual(self._mode(self.path), 0o600)
        self.assertEqual(self._leftovers(), [])

    def test_empty_file(self):
        write_private_atomic(self.path, b"")
        self.assertEqual(self.path.read_bytes(), b"")
        self.assertEqual(self._mode(self.path), 0o600)

    def test_reasonably_large_file(self):
        data = secrets.token_bytes(8 * 1024 * 1024)
        write_private_atomic(self.path, data)
        self.assertEqual(self.path.read_bytes(), data)
        self.assertEqual(self._leftovers(), [])

    def test_replaces_existing_file_and_its_permissions(self):
        self.path.write_bytes(b"ancien")
        os.chmod(self.path, 0o644)
        write_private_atomic(self.path, b"nouveau")
        self.assertEqual(self.path.read_bytes(), b"nouveau")
        self.assertEqual(self._mode(self.path), 0o600)

    def test_creates_missing_parent_directory(self):
        target = self.dir / "a" / "b" / "fichier.bin"
        write_private_atomic(target, b"x")
        self.assertEqual(target.read_bytes(), b"x")

    def test_temporary_file_is_private_and_in_the_same_directory(self):
        seen = {}
        real_replace = os.replace

        def spy(src, dst):
            src = Path(src)
            seen.update(parent=src.parent, name=src.name, mode=self._mode(src))
            real_replace(src, dst)

        with mock.patch.object(files.os, "replace", side_effect=spy):
            write_private_atomic(self.path, b"x", temp_prefix=".tmp-test-", temp_suffix=".bin")
        self.assertEqual(seen["parent"], self.dir)
        self.assertTrue(seen["name"].startswith(".tmp-test-"))
        self.assertTrue(seen["name"].endswith(".bin"))
        self.assertEqual(seen["mode"], 0o600)

    def test_existing_file_preserved_when_replace_fails(self):
        self.path.write_bytes(b"version valide")
        with mock.patch.object(files.os, "replace", side_effect=OSError("disque plein")), \
                self.assertRaises(OSError):
            write_private_atomic(self.path, b"nouvelle version")
        self.assertEqual(self.path.read_bytes(), b"version valide")
        self.assertEqual(self._leftovers(), [])

    def test_existing_file_preserved_when_write_fails(self):
        self.path.write_bytes(b"version valide")
        with mock.patch.object(files.os, "fsync", side_effect=OSError("erreur d'E/S")), \
                self.assertRaises(OSError):
            write_private_atomic(self.path, b"nouvelle version")
        self.assertEqual(self.path.read_bytes(), b"version valide")
        self.assertEqual(self._leftovers(), [])

    def test_interrupted_write_leaves_no_file(self):
        # Interruption (Ctrl+C) pendant l'écriture : ni destination, ni temporaire.
        with mock.patch.object(files.os, "fsync", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            write_private_atomic(self.path, b"x")
        self.assertFalse(self.path.exists())
        self.assertEqual(self._leftovers(), [])

    def test_file_and_directory_are_synced(self):
        real_fsync = os.fsync
        with mock.patch.object(files.os, "fsync", side_effect=real_fsync) as fsync:
            write_private_atomic(self.path, b"x")
        self.assertGreaterEqual(fsync.call_count, 2)  # fichier puis dossier

    def test_directory_sync_failure_is_not_fatal(self):
        real_open = os.open

        def refuse_directories(path, flags, *args):
            if Path(path) == self.dir:
                raise PermissionError("dossier non ouvrable")
            return real_open(path, flags, *args)

        with mock.patch.object(files.os, "open", side_effect=refuse_directories):
            write_private_atomic(self.path, b"x")
        self.assertEqual(self.path.read_bytes(), b"x")


class TestCallersUsePrivateAtomicWrites(unittest.TestCase):
    """Les services passent tous par la primitive commune."""

    def test_no_other_private_write_implementation(self):
        app_dir = Path(__file__).resolve().parent.parent / "app"
        offenders = [str(p.relative_to(app_dir)) for p in app_dir.rglob("*.py")
                     if p.name != "files.py" and "mkstemp" in p.read_text(encoding="utf-8")]
        self.assertEqual(offenders, [])
