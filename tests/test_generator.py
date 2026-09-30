import ast
import math
import string
import unittest
from pathlib import Path

from app.core import generator
from app.core.generator import (
    AMBIGUOUS,
    SYMBOLS,
    GeneratorError,
    PassphraseOptions,
    PasswordOptions,
    WordlistUnavailableError,
    generate_passphrase,
    generate_password,
    passphrase_available,
)

APP_DIR = Path(__file__).resolve().parent.parent / "app"


class TestNoInsecureRandomness(unittest.TestCase):
    def test_random_module_never_imported_in_app(self):
        offenders = []
        for path in APP_DIR.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                if any(n == "random" or n.startswith("random.") for n in names):
                    offenders.append(str(path.relative_to(APP_DIR)))
        self.assertEqual(offenders, [], "Le module `random` ne doit jamais être utilisé.")


class TestPasswordGenerator(unittest.TestCase):
    def test_length_and_all_classes_present(self):
        for length in (8, 20, 64, 128):
            value = generate_password(PasswordOptions(length=length)).value
            self.assertEqual(len(value), length)
            self.assertTrue(any(c in string.ascii_lowercase for c in value))
            self.assertTrue(any(c in string.ascii_uppercase for c in value))
            self.assertTrue(any(c in string.digits for c in value))
            self.assertTrue(any(c in SYMBOLS for c in value))

    def test_only_selected_classes(self):
        value = generate_password(
            PasswordOptions(length=40, uppercase=False, symbols=False)
        ).value
        self.assertTrue(set(value) <= set(string.ascii_lowercase + string.digits))

    def test_exclude_ambiguous(self):
        for _ in range(50):
            value = generate_password(PasswordOptions(length=64, exclude_ambiguous=True)).value
            self.assertFalse(set(value) & AMBIGUOUS)

    def test_invalid_options(self):
        with self.assertRaises(GeneratorError):
            generate_password(PasswordOptions(length=7))
        with self.assertRaises(GeneratorError):
            generate_password(PasswordOptions(length=129))
        with self.assertRaises(GeneratorError):
            generate_password(PasswordOptions(lowercase=False, uppercase=False,
                                              digits=False, symbols=False))

    def test_values_are_unique(self):
        values = {generate_password().value for _ in range(500)}
        self.assertEqual(len(values), 500)

    def test_entropy(self):
        result = generate_password(PasswordOptions(length=20))
        pool = 26 + 26 + 10 + len(SYMBOLS)
        self.assertAlmostEqual(result.entropy_bits, 20 * math.log2(pool))

    def test_repr_hides_value(self):
        result = generate_password()
        self.assertNotIn(result.value, repr(result))


@unittest.skipUnless(passphrase_available(), "Liste de mots (wfrench) absente")
class TestPassphraseGenerator(unittest.TestCase):
    def test_word_count_and_membership(self):
        wordlist = set(generator.load_passphrase_wordlist())
        value = generate_passphrase(PassphraseOptions(words=7, separator="-")).value
        words = value.split("-")
        self.assertEqual(len(words), 7)
        self.assertTrue(all(w in wordlist for w in words))

    def test_options(self):
        value = generate_passphrase(
            PassphraseOptions(words=5, separator=" ", capitalize=True, add_number=True)
        ).value
        words = value.split(" ")
        self.assertEqual(len(words), 5)
        self.assertTrue(all(w[0].isupper() for w in words))
        self.assertEqual(sum(c.isdigit() for c in value), 1)

    def test_entropy_default_is_high(self):
        self.assertGreater(generate_passphrase().entropy_bits, 80)

    def test_invalid_word_count(self):
        with self.assertRaises(GeneratorError):
            generate_passphrase(PassphraseOptions(words=3))


class TestMissingWordlist(unittest.TestCase):
    def test_clear_error_naming_the_debian_package(self):
        original = generator.FRENCH_WORDLIST_PATH
        generator.load_passphrase_wordlist.cache_clear()
        generator.FRENCH_WORDLIST_PATH = Path("/chemin/inexistant/french")
        try:
            with self.assertRaises(WordlistUnavailableError) as ctx:
                generate_passphrase()
            self.assertIn("wfrench", str(ctx.exception))
            self.assertFalse(passphrase_available())
        finally:
            generator.FRENCH_WORDLIST_PATH = original
            generator.load_passphrase_wordlist.cache_clear()


if __name__ == "__main__":
    unittest.main()
