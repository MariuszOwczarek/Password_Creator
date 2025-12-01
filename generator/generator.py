from policy.policy import PasswordPolicy
from policy.errors import PolicyError
import random


class PasswordGenerator:
    def __init__(self, policy: PasswordPolicy):
        self.policy = policy

    def _get_target_length(self):
        """
            Wybiera docelową długość hasła z przedziału [min_val, max_val],
            ale gwarantuje, że min_val >= required_count (liczba
            wymaganych kategorii). Rzuca PolicyError jeśli polityka jest
            niespełnialna.
        """
        min_val = self.policy.length_min
        max_val = (self.policy.length_max
                   if self.policy.length_max is not None
                   else min_val)

        if not isinstance(min_val, int) or not isinstance(max_val, int):
            raise PolicyError("length_min and length_max must be integers")

        if min_val <= 0:
            raise PolicyError("length_min must be > 0")

        if min_val > max_val:
            raise PolicyError("length_min must be <= length_max")

        required_count = sum((
            1 if self.policy.require_upper else 0,
            1 if self.policy.require_lower else 0,
            1 if self.policy.require_digits else 0,
            1 if self.policy.require_specials else 0,
            ))

        if required_count > max_val:
            raise PolicyError("PolicyError: required categories exceed "
                              "length_max — policy impossible to satisfy")

        effective_min = max(min_val, required_count)

        chosen_length = random.randint(effective_min, max_val)
        return chosen_length

    def _add_upper(self):
        random_char = chr(random.randint(65, 90))
        return random_char

    def _add_lower(self):
        random_char = chr(random.randint(97, 122))
        return random_char

    def _add_digits(self):
        random_char = str(random.randint(0, 9))
        return random_char

    def _add_specials(self):
        if not self.policy.allowed_specials:
            raise PolicyError("PolicyError: No allowed specials defined "
                              "in policy.")
        random_char = random.choice(self.policy.allowed_specials)
        return random_char

    def _shuffle(self, password):
        random.shuffle(password)
        return ''.join(password)

    def check_max_consecutive(self, password, max_count):
        if max_count is None:
            return True
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                count += 1
                if count > max_count:
                    return False
            else:
                count = 1
        return True

    def _check_deny_substrings(self, password):
        if self.policy.deny_substrings is None:
            return True
        for substring in self.policy.deny_substrings:
            if substring in password:
                return False
        return True

    def generate(self, max_attempts=1000):
        attempts = 0
        while True:
            password_chars = []
            target_length = self._get_target_length()

            if self.policy.require_upper:
                password_chars.append(self._add_upper())
            if self.policy.require_lower:
                password_chars.append(self._add_lower())
            if self.policy.require_digits:
                password_chars.append(self._add_digits())
            if self.policy.require_specials:
                password_chars.append(self._add_specials())

            while len(password_chars) < target_length:
                available_generators = [self._add_upper, self._add_lower,
                                        self._add_digits]

                if self.policy.require_specials:
                    available_generators.append(self._add_specials)
                password_chars.append(random.choice(available_generators)())

            password = self._shuffle(password_chars)

            if (self.check_max_consecutive(password,
                                           self.policy.max_consecutive_same)
               and self._check_deny_substrings(password)):
                return password
            attempts += 1
            if attempts >= max_attempts:
                raise PolicyError(
                    f"unable to generate password after {max_attempts} "
                    "attempts; policy too restrictive")
