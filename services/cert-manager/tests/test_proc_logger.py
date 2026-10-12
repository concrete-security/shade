"""Bound log forwarding without losing append or rotation progress."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def logger_module():
    path = Path(__file__).parents[1] / "proc_logger.py"
    spec = importlib.util.spec_from_file_location("proc_logger", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tail_passes(module, logger, monkeypatch, count):
    completed = 0

    def sleep(_seconds):
        nonlocal completed
        completed += 1
        if completed >= count:
            logger.running = False

    logger.running = True
    monkeypatch.setattr(module.time, "sleep", sleep)
    logger._tail_file("nginx")


def test_large_backlog_bounded_success(logger_module, tmp_path, monkeypatch, capsys):
    """A backlog leaves unread records for the next pass rather than buffering all records."""
    path = tmp_path / "nginx.log"
    path.write_text("request completed\n" * 5000)
    logger = logger_module.ProcessLogger({"nginx": str(path)})
    logger._open_log_files()
    capsys.readouterr()
    try:
        tail_passes(logger_module, logger, monkeypatch, 1)
        output = capsys.readouterr().out.splitlines()
        assert output == ["[nginx] request completed"] * 1024
        assert logger.file_handles["nginx"].tell() < path.stat().st_size
    finally:
        logger.stop()


@pytest.mark.parametrize("ending", ["", "\n"])
def test_oversized_record_split_success(logger_module, tmp_path, monkeypatch, capsys, ending):
    """An oversized record is forwarded in bounded chunks with its contents preserved."""
    path = tmp_path / "nginx.log"
    content = "x" * (65536 * 3 + 17)
    path.write_text(content + ending)
    logger = logger_module.ProcessLogger({"nginx": str(path)})
    logger._open_log_files()
    capsys.readouterr()
    try:
        tail_passes(logger_module, logger, monkeypatch, 1)
        chunks = [line.removeprefix("[nginx] ") for line in capsys.readouterr().out.splitlines()]
        assert max(map(len, chunks)) <= 65536
        assert "".join(chunks) == content
    finally:
        logger.stop()


def test_rotated_log_followed_success(logger_module, tmp_path, monkeypatch, capsys):
    """Drain the opened file and then follow a new file at the same path."""
    path = tmp_path / "nginx.log"
    path.write_text("before rotation\n")
    logger = logger_module.ProcessLogger({"nginx": str(path)})
    logger._open_log_files()
    old_handle = logger.file_handles["nginx"]
    capsys.readouterr()
    path.rename(tmp_path / "nginx.log.1")
    path.write_text("after rotation\n")
    try:
        tail_passes(logger_module, logger, monkeypatch, 2)
        assert capsys.readouterr().out.splitlines() == [
            "[nginx] before rotation",
            "[nginx] after rotation",
        ]
        assert old_handle.closed
    finally:
        logger.stop()


def test_truncated_log_followed_success(logger_module, tmp_path, monkeypatch, capsys):
    """An in-place truncation must not leave the reader beyond the new end."""
    path = tmp_path / "nginx.log"
    path.write_text("original long record\n")
    logger = logger_module.ProcessLogger({"nginx": str(path)})
    logger._open_log_files()
    logger.file_handles["nginx"].read()
    capsys.readouterr()
    path.write_text("new\n")
    try:
        tail_passes(logger_module, logger, monkeypatch, 1)
        assert capsys.readouterr().out == "[nginx] new\n"
    finally:
        logger.stop()


def test_missing_rotation_path_retried_success(logger_module, tmp_path, monkeypatch, capsys):
    """A transiently absent path must keep the old reader usable."""
    path = tmp_path / "nginx.log"
    path.write_text("before rename\n")
    logger = logger_module.ProcessLogger({"nginx": str(path)})
    logger._open_log_files()
    old_handle = logger.file_handles["nginx"]
    capsys.readouterr()
    path.rename(tmp_path / "nginx.log.1")
    try:
        tail_passes(logger_module, logger, monkeypatch, 1)
        assert capsys.readouterr().out == "[nginx] before rename\n"
        assert not old_handle.closed
        path.write_text("after rename\n")
        tail_passes(logger_module, logger, monkeypatch, 2)
        assert capsys.readouterr().out == "[nginx] after rename\n"
    finally:
        logger.stop()
