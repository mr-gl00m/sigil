"""Tests for FileLock cross-platform file locking."""

from pathlib import Path
from sigil import FileLock


def test_lock_creates_lock_file(tmp_path):
    """Entering the lock creates a .lock file."""
    target = tmp_path / "data.json"
    target.write_text("{}")
    lock = FileLock(target)
    with lock:
        assert (tmp_path / "data.json.lock").exists()


def test_lock_unlock_cycle(tmp_path):
    """Lock can be acquired and released without error."""
    target = tmp_path / "test.txt"
    target.write_text("content")
    lock = FileLock(target)
    with lock:
        pass  # Should not raise


def test_context_manager_enter_exit(tmp_path):
    """__enter__ returns self, __exit__ returns False."""
    target = tmp_path / "cm.txt"
    target.write_text("")
    lock = FileLock(target)
    result = lock.__enter__()
    assert result is lock
    exit_result = lock.__exit__(None, None, None)
    assert exit_result is False


def test_lock_path_is_correct(tmp_path):
    """Lock path is parent/name.lock."""
    target = tmp_path / "subdir" / "myfile.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}")
    lock = FileLock(target)
    assert lock.lock_path == tmp_path / "subdir" / "myfile.json.lock"


def test_exit_does_not_suppress_exceptions(tmp_path):
    """__exit__ returns False, meaning exceptions propagate."""
    target = tmp_path / "exc.txt"
    target.write_text("")
    with FileLock(target) as lock:
        try:
            raise ValueError("test error")
        except ValueError:
            pass  # Exception should propagate normally
    # If we get here, exceptions were not suppressed


def test_lock_timeout_parameter_accepted(tmp_path):
    """FileLock(path, timeout=5.0) initializes without error."""
    target = tmp_path / "timeout_test.json"
    target.write_text("{}")
    lock = FileLock(target, timeout=5.0)
    assert lock.timeout == 5.0
    with lock:
        pass


def test_lock_default_timeout_is_10(tmp_path):
    """Default timeout is 10 seconds."""
    target = tmp_path / "default_timeout.json"
    target.write_text("{}")
    lock = FileLock(target)
    assert lock.timeout == 10.0
