from policy.policy import PasswordPolicy
from policy.errors import PolicyError
import random


class PasswordGenerator:
    def __init__(self, policy: PasswordPolicy):
        self.policy = policy
        self.password = []

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

    def generate(self):

        while True:
            password_chars = []
            if self.policy.require_upper:
                password_chars.append(self._add_upper())
            if self.policy.require_lower:
                password_chars.append(self._add_lower())
            if self.policy.require_digits:
                password_chars.append(self._add_digits())
            if self.policy.require_specials:
                password_chars.append(self._add_specials())

            while len(password_chars) < self.policy.length_min:
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


policy = PasswordPolicy(length_min=15)
generator = PasswordGenerator(policy)
password = generator.generate()

print('Policy details:')
for k, v in policy.__dict__.items():
    print(f'{k}: {v}')
print(f'Password: {password}')
