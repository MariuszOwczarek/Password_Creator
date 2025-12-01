from policy.errors import PolicyError
from policy.policy import PasswordPolicy
from generator.generator import PasswordGenerator

if __name__ == "__main__":
    try:
        policy = PasswordPolicy(
            length_min=20,
            length_max=30,
            require_upper=True,
            require_lower=True,
            require_digits=True,
            require_specials=True,
            allowed_specials=['%', '!', '@', '+'],
            deny_substrings=['p%', 'a!'],
            max_consecutive_same=2,
            no_whitespace=True
        )

        generator = PasswordGenerator(policy)
        password = generator.generate()

        print(f'Password: {password}\nlength:{len(password)}')

    except PolicyError as e:
        print(f"Policy error: {e}")
