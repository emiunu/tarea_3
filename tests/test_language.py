from miner.language import detect_codeql_language, is_supported


def test_python_is_supported():
    assert detect_codeql_language("Python") == "python"
    assert is_supported("Python") is True


def test_typescript_maps_to_javascript_extractor():
    assert detect_codeql_language("TypeScript") == "javascript"


def test_unsupported_language_returns_none():
    assert detect_codeql_language("HCL") is None
    assert is_supported("HCL") is False


def test_missing_language_is_not_supported():
    assert detect_codeql_language(None) is None
    assert is_supported(None) is False