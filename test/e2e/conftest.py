import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "filterwarnings",
        "ignore::DeprecationWarning:undetected_chromedriver",
    )
