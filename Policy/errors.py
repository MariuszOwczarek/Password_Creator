class PolicyError(Exception):
    """
        Exception raised for invalid password policy configuration.

        Attributes:
            message (str): Human-readable explanation of the error.
    """

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message
