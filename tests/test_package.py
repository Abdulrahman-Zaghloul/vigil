import re

import vigil


def test_package_imports_and_has_a_semantic_version() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", vigil.__version__)
