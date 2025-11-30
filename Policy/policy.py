from typing import Optional, Sequence
from Policy.errors import PolicyError

MAX_ALLOWED_LENGTH = 1024


class PasswordPolicy:

    """
        Represents a configuration object defining password validation rules.

        This class encapsulates all constraints that define what is considered
        a valid password in the system. It supports settings such as minimum
        and maximum length, required character types, allowed special
        characters,forbidden substrings, whitespace rules, and restrictions
        on consecutive character repetition.

        Args:
            length_min (int): Minimum allowed password length.
                Must be > 0.
            length_max (int): Maximum allowed password length.
                Must be >= length_min.
            require_upper (bool): Whether the password must include
                uppercase letters.
            require_lower (bool): Whether the password must include
                lowercase letters.
            require_digits (bool): Whether the password must include
                at least one digit.
            require_specials (bool): Whether the password must include
                at least one special character from `allowed_specials`.
            allowed_specials (Optional[Sequence[str]]): A sequence of
                allowed special characters. Required if `require_specials=True`
                Cannot include whitespace if `no_whitespace=True`.
            deny_substrings (Optional[Sequence[str]]): A list of
                forbidden substrings. If any substring from this list appears
                in the password, validation fails.
            max_consecutive_same (int | None): Maximum number of
                identical characters allowed in a row. Must be >= 1 if provided
                None disables this rule.
            no_whitespace (bool): Whether whitespace characters are forbidden.

        Raises:
            PolicyError: If any provided rule is invalid, inconsistent,
                or logically contradictory (e.g., require_specials=True with
                empty allowed_specials).
    """

    def __init__(self,
                 length_min: int = 12,
                 length_max: int = 24,
                 require_upper: bool = True,
                 require_lower: bool = True,
                 require_digits: bool = True,
                 require_specials: bool = False,
                 allowed_specials: Optional[Sequence[str]] = None,
                 deny_substrings: Optional[Sequence[str]] = None,
                 max_consecutive_same: int | None = None,
                 no_whitespace: bool = True
                 ):

        self.length_min = length_min
        self.length_max = length_max
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digits = require_digits
        self.require_specials = require_specials
        self.allowed_specials = allowed_specials
        self.deny_substrings = deny_substrings
        self.max_consecutive_same = max_consecutive_same
        self.no_whitespace = no_whitespace
        self.validate_rules()

    def validate_rules(self):

        """
            Validates all policy settings for logical consistency.

            This method ensures that numeric values fall within valid ranges,
            boolean rule combinations are meaningful, forbidden substrings
            are well defined, and special character limitations are consistent
            with whitespace rules.

            Raises:
                PolicyError: If any part of the configuration is invalid.
        """

        if not isinstance(self.length_min, int):
            raise PolicyError("PolicyError: length_min and length_max "
                              "must be integers")

        if not isinstance(self.length_max, int):
            raise PolicyError("PolicyError: length_min and length_max "
                              "must be integers")

        if self.length_min <= 0 or self.length_max <= 0:
            raise PolicyError("PolicyError: length_min and length_max "
                              "must be > 0")

        if self.length_min > self.length_max:
            raise PolicyError("PolicyError: length_min must be <= length_max")

        if self.require_specials:
            if not isinstance(self.allowed_specials, (list, tuple)):
                raise PolicyError("allowed_specials must be a list or tuple "
                                  "of strings")
            if not self.allowed_specials:
                raise PolicyError("allowed_specials must not be empty")

            for c in self.allowed_specials:
                if not isinstance(c, str) or len(c) != 1:
                    raise PolicyError("allowed_specials must contain only "
                                      "single-character strings")

        if self.deny_substrings is not None:
            if not isinstance(self.deny_substrings, (list, tuple)):
                raise PolicyError("PolicyError: deny_substrings must be a "
                                  "list of strings")
            if not all(isinstance(s, str) for s in self.deny_substrings):
                raise PolicyError("PolicyError: all deny_substrings must "
                                  "be strings")
            if any(s == "" for s in self.deny_substrings):
                raise PolicyError("deny_substrings must not contain "
                                  "empty strings")

        if (self.length_min > MAX_ALLOWED_LENGTH or
           self.length_max > MAX_ALLOWED_LENGTH):
            raise PolicyError("PolicyError: length_min or length_max value "
                              "(must be <= 1024)")

        if (self.no_whitespace and self.allowed_specials is not None
           and any(c.isspace() for c in self.allowed_specials)):
            raise PolicyError("PolicyError: Special characters cannot "
                              "have whitespaces")
        if (self.max_consecutive_same is not None and
                self.max_consecutive_same < 1):
            raise PolicyError("PolicyError: max_consecutive_same "
                              "Must be >= 1")

        required_count = sum([self.require_upper, self.require_lower,
                              self.require_digits, self.require_specials])
        if required_count > self.length_max:
            raise PolicyError("PolicyError: length_max must be "
                              ">= required_count")

    def to_dict(self) -> dict:
        """
            Converts the policy instance into a serializable dictionary.

            Returns:
                dict: A dictionary representation of the current policy,
                    suitable for serialization (e.g., saving to JSON
                    or config files).
        """

        return {
            "length_min": self.length_min,
            "length_max": self.length_max,
            "require_upper": self.require_upper,
            "require_lower": self.require_lower,
            "require_digits": self.require_digits,
            "require_specials": self.require_specials,
            "allowed_specials": self.allowed_specials,
            "deny_substrings": self.deny_substrings,
            "max_consecutive_same": self.max_consecutive_same,
            "no_whitespace": self.no_whitespace
            }

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordPolicy":
        """
            Creates a PasswordPolicy instance using a dictionary of settings.

            This is the inverse operation of `to_dict()` and is particularly
            useful when loading policy configurations from JSON or other
            serialized formats.

            Args:
                data (dict): A dictionary containing policy fields.
                    Missing fields fall back to default values defined in the
                    constructor.

            Returns:
                PasswordPolicy: A fully constructed policy instance based
                    on the provided configuration dictionary.
        """

        length_min = data.get("length_min", 12)
        length_max = data.get("length_max", 24)
        require_upper = data.get("require_upper", True)
        require_lower = data.get("require_lower", True)
        require_digits = data.get("require_digits", True)
        require_specials = data.get("require_specials", False)
        allowed_specials = data.get("allowed_specials", None)
        deny_substrings = data.get("deny_substrings", None)
        max_consecutive_same = data.get("max_consecutive_same", None)
        no_whitespace = data.get("no_whitespace", True)

        return cls(
            length_min=length_min,
            length_max=length_max,
            require_upper=require_upper,
            require_lower=require_lower,
            require_digits=require_digits,
            require_specials=require_specials,
            allowed_specials=allowed_specials,
            deny_substrings=deny_substrings,
            max_consecutive_same=max_consecutive_same,
            no_whitespace=no_whitespace
        )


if __name__ == "__main__":
    pp = PasswordPolicy(length_min=10,
                        length_max=12,
                        require_upper=True,
                        require_lower=True,
                        require_digits=True,
                        require_specials=False,
                        allowed_specials=['%', '!', '@'],
                        deny_substrings=['password', 'admin'],
                        max_consecutive_same=3,
                        no_whitespace=True)

    for k, v in pp.to_dict().items():
        print(f'{k}:{v}')
