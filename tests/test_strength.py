import unittest

from app.core.generator import PasswordOptions, generate_password
from app.core.strength import dictionary_available, estimate_strength


class TestStrength(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(estimate_strength("").score, 0)

    def test_common_passwords_are_very_weak(self):
        for pw in ("password", "P@ssw0rd", "azerty", "123456789", "motdepasse", "Soleil"):
            self.assertEqual(estimate_strength(pw).score, 0, pw)

    def test_patterns_are_penalised(self):
        for pw in ("aaaaaaaaaaaa", "abcdefghijkl", "azertyuiop12", "qsdfghjklm"):
            self.assertLessEqual(estimate_strength(pw).score, 1, pw)

    @unittest.skipUnless(dictionary_available(), "dictionnaires absents")
    def test_word_plus_year_is_weak(self):
        for pw in ("Soleil2024!", "Jean1985", "Chocolat1990"):
            self.assertLessEqual(estimate_strength(pw).score, 1, pw)

    def test_random_passwords_are_strong(self):
        for _ in range(50):
            pw = generate_password(PasswordOptions(length=20)).value
            result = estimate_strength(pw)
            self.assertEqual(result.score, 4, result)
            self.assertEqual(result.warnings, ())

    def test_longer_is_stronger(self):
        base = "kX9#mQ2$"
        self.assertLess(estimate_strength(base).entropy_bits,
                        estimate_strength(base + "vL7pR4!w").entropy_bits)

    def test_short_password_gets_length_advice(self):
        result = estimate_strength("kX9#mQ")
        self.assertTrue(any("12 caractères" in w for w in result.warnings))


if __name__ == "__main__":
    unittest.main()
