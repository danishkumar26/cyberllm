"""Tests for CyberLLM parsers."""

from cyberllm.parsers import PARSERS, parse_apache, parse_file, parse_json, parse_syslog

SAMPLE_SYSLOG = """May 10 10:15:22 myserver sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
May 10 10:15:23 myserver sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 23 ssh2
May 10 10:15:24 myserver sshd[1234]: Accepted password for jdoe from 10.0.0.5 port 22 ssh2
"""

SAMPLE_JSON = """{"timestamp": "2024-01-01T00:00:00Z", "hostname": "web01", "service": "nginx", "message": "GET /index.html 200", "source_ip": "1.2.3.4", "user": "anonymous"}
{"timestamp": "2024-01-01T00:00:01Z", "hostname": "web01", "service": "nginx", "message": "POST /login 403", "source_ip": "9.9.9.9", "user": "attacker"}
"""

SAMPLE_APACHE = """1.2.3.4 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
5.6.7.8 - - [10/Oct/2023:13:55:37 -0700] "POST /login HTTP/1.1" 403 512 "-" "curl/7.68.0"
"""


def test_parse_syslog():
    import os
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_SYSLOG)
        path = f.name
    try:
        result = parse_syslog(path)
        assert len(result.entries) == 3
        assert result.entries[0].service == "sshd"
        assert result.entries[0].source_ip == "203.0.113.5"
        assert result.parse_errors == 0
    finally:
        os.unlink(path)


def test_parse_json():
    import os
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(SAMPLE_JSON)
        path = f.name
    try:
        result = parse_json(path)
        assert len(result.entries) == 2
        assert result.entries[0].source_ip == "1.2.3.4"
        assert result.entries[1].user == "attacker"
    finally:
        os.unlink(path)


def test_parse_apache():
    import os
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_APACHE)
        path = f.name
    try:
        result = parse_apache(path)
        assert len(result.entries) == 2
        assert result.entries[0].source_ip == "1.2.3.4"
        assert result.entries[1].message.startswith("POST /login 403")
    finally:
        os.unlink(path)


def test_auto_detect_json():
    import os
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_JSON)
        path = f.name
    try:
        result = parse_file(path)
        assert len(result.entries) == 2
    finally:
        os.unlink(path)


def test_auto_detect_syslog():
    import os
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_SYSLOG)
        path = f.name
    try:
        result = parse_file(path)
        assert len(result.entries) == 3
    finally:
        os.unlink(path)


def test_parsers_registry():
    assert "syslog" in PARSERS
    assert "json" in PARSERS
    assert "apache" in PARSERS
    assert "windows_event" in PARSERS
