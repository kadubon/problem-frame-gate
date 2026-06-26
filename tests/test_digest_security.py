from problem_frame_gate import digest_json, scan_for_sensitive_data


def test_digest_is_key_order_independent() -> None:
    assert digest_json({"b": 2, "a": 1}) == digest_json({"a": 1, "b": 2})


def test_sensitive_scanner_flags_secret_key_names() -> None:
    issues = scan_for_sensitive_data({"api_key": "sk-test12345678901234567890"})
    assert issues
    assert issues[0].path == "$.api_key"


def test_sensitive_scanner_flags_local_paths() -> None:
    issues = scan_for_sensitive_data({"source": "/home/example/.ssh/id_ed25519"})
    assert issues
