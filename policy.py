from typing import Optional, Sequence, List
from errors import PolicyError


class PasswordPolicy:
    def __init__(self,
                 length_min: int = 12,
                 length_max: int = 24,
                 require_upper: bool = True,
                 require_lower: bool = True,
                 require_digits: bool = True,
                 require_specials: bool = False,
                 allowed_specials: Optional[Sequence[str]] = None,
                 deny_substrings: Optional[List[str]] = None,
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
        if not isinstance(self.length_min, int):
            raise PolicyError("Policy Error: length_min and length_max "
                              "must be integers")

        if not isinstance(self.length_max, int):
            raise PolicyError("Policy Error: length_min and length_max "
                              "must be integers")

        if self.length_min <= 0 or self.length_max <= 0:
            raise PolicyError("Policy Error: length_min and length_max "
                              "must be > 0")

        if self.length_min > self.length_max:
            raise PolicyError("Policy Error: length_min must be <= length_max")

        if (
            self.require_specials is True and
            (self.allowed_specials is None or len(self.allowed_specials) == 0)
        ):
            raise PolicyError("Policy Error: allowed_specials must be a string"
                              "or list of single-character strings")

        if (
            self.deny_substrings is not None
            and not isinstance(self.deny_substrings, list)
        ):
            raise PolicyError("Policy Error: deny_substrings must be a "
                              "list of strings")

        if self.length_min > 1024 or self.length_max > 1024:
            raise PolicyError("Policy Error: length values are too large")

    def to_dict(self) -> dict:
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
    def from_dict(cls, data: dict):
        pass


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
