def execute_expression(user_input: str):
    # Deterministic internal parity fixture: this line is intentionally matched
    # by the repository-owned Semgrep rule below.
    return eval(user_input)
