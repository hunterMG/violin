"""Policy for the built-in Hermes terminal tool.

Violin keeps the built-in ``terminal`` tool available for host-local work, but
raw terminal calls must not become an escape hatch around the typed Violin
execution boundary.  This module is intentionally a conservative, pure
classifier: it blocks commands that are clearly target-touching and leaves
ordinary local development/bookkeeping commands available.

The typed ``violin_exec`` and ``violin_exec_burst`` tools remain the authoritative
path for target commands because they carry the engagement, scope, phase, PTT,
hypothesis, history, evidence, and sync arguments needed by the full guard.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import shlex
from urllib.parse import urlsplit

from .terminal_rules import (
    _COMMAND_SPLIT_RE,
    _COMMAND_SUBSTITUTION_RE,
    _DOMAIN_RE,
    _IPV4_RE,
    _KNOWN_SOURCE_HOSTS,
    _LOCAL_COMMANDS,
    _LOCAL_FILE_SUFFIXES,
    _NETWORK_MODULE_RE,
    _NETWORK_PATH_RE,
    _PACKAGE_OR_SOURCE_COMMANDS,
    _SCRIPT_INTERPRETERS,
    _SHELL_WRAPPERS,
    _SUSPICIOUS_SCRIPT_RE,
    _URL_RE,
)


def _command_words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        # An incomplete quote is not a reason to let a possibly dangerous
        # command through.  The fallback is only used for classification.
        return re.findall(r"[^\s]+", segment)


def _basename(value: str) -> str:
    return re.split(r"[/\\]", value.rsplit("=", 1)[-1])[-1].lower()


def _first_executable(segment: str) -> str:
    words = _command_words(segment)
    index = 0
    while index < len(words):
        word = words[index]
        lower = word.lower()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", word):
            index += 1
            continue
        if lower in {"command", "env", "exec", "nice", "sudo", "timeout"}:
            index += 1
            if lower == "timeout" and index < len(words):
                index += 1
            continue
        return _basename(word)
    return ""


def _is_package_or_source_command(command: str) -> bool:
    executable = _first_executable(command)
    return executable in _PACKAGE_OR_SOURCE_COMMANDS


def _url_hosts(command: str) -> list[str]:
    hosts: list[str] = []
    for match in _URL_RE.finditer(command):
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            host = None
        if host:
            hosts.append(host)
    return hosts


def _is_known_source_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    return any(
        normalized == known or normalized.endswith(f".{known}") for known in _KNOWN_SOURCE_HOSTS
    )


def _word_is_target_literal(word: str) -> bool:
    """Inspect a single shell word token for an IP address, remote URL, or domain literal."""
    value = word.strip("'\"()[]{}<>,")
    authority = value.rsplit("@", 1)[-1]
    if authority.count(":") == 1:
        authority = authority.split(":", 1)[0]

    if _IPV4_RE.fullmatch(authority):
        return authority not in {"127.0.0.1", "0.0.0.0"}

    with contextlib.suppress(ValueError):
        clean_ip = authority.strip("[]")
        ip_obj = ipaddress.ip_address(clean_ip)
        return not ip_obj.is_loopback and not ip_obj.is_unspecified

    if "://" in value:
        try:
            hostname = urlsplit(value).hostname
            return bool(
                hostname and hostname.lower() not in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
            )
        except ValueError:
            return True

    # Paths and ordinary local scripts are not host literals
    if "/" in value or "\\" in value or value.startswith("."):
        return False
    if authority.lower() in {"localhost"}:
        return False
    if any(value.lower().endswith(suffix) for suffix in _LOCAL_FILE_SUFFIXES):
        return False

    return bool(_DOMAIN_RE.fullmatch(authority))


def _has_target_literal(command: str) -> bool:
    """Inspect shell arguments, not arbitrary source code or file paths."""
    for segment in _COMMAND_SPLIT_RE.split(command):
        words = _command_words(segment)
        executable = _first_executable(segment)
        # Shell `-c` strings are commands and must still be inspected. Source
        # passed to language runtimes is skipped to avoid classifying an IP
        # literal inside ordinary local code as a network action.
        skip_code = (
            executable in _SCRIPT_INTERPRETERS
            and executable not in _SHELL_WRAPPERS
            and "-c" in words
        )
        c_index = words.index("-c") if skip_code else -1
        for index, word in enumerate(words):
            if skip_code and index > c_index:
                continue
            if _word_is_target_literal(word):
                return True
    return False


def _is_violin_init_command(segment: str) -> bool:
    """Return whether ``segment`` invokes Violin's host-local bootstrap command."""
    if _first_executable(segment) not in {"python", "python3"}:
        return False
    words = _command_words(segment)
    for index, word in enumerate(words):
        script = word.replace("\\", "/").removeprefix("./")
        if (
            (script == "scripts/violin_guard.py" or script.endswith("/scripts/violin_guard.py"))
            and index + 1 < len(words)
            and words[index + 1] == "init-engagement"
        ):
            return True
    return False


def _dynamic_init_host(segment: str) -> bool:
    """Reject host indirection while allowing variables in local path arguments."""
    words = _command_words(segment)
    for index, word in enumerate(words):
        if word == "--host" and index + 1 < len(words):
            return "$" in words[index + 1] or "`" in words[index + 1]
        if word.startswith("--host="):
            host = word.partition("=")[2]
            return "$" in host or "`" in host
    return False


def _is_local_compilation_or_test(segment: str) -> bool:
    """Return True if the command is a local syntax compile check or test framework invocation."""
    words = _command_words(segment)
    lower_words = [w.lower() for w in words]
    if "-m" in lower_words:
        idx = lower_words.index("-m")
        if idx + 1 < len(lower_words) and lower_words[idx + 1] in {
            "py_compile",
            "pytest",
            "unittest",
            "doctest",
        }:
            return True
    return "py_compile" in segment or "pytest" in lower_words or "unittest" in lower_words


def _block_terminal_segment(segment: str) -> str | None:
    if _NETWORK_PATH_RE.search(segment):
        return _message("network socket path detected in the raw terminal command")

    executable = _first_executable(segment)
    if executable in _SCRIPT_INTERPRETERS and _NETWORK_MODULE_RE.search(segment):
        return _message("network-capable script primitive detected in the raw terminal command")

    # Package/source retrieval is allowed for local setup (for example git
    # clone or pip install).  URLs and host literals in all other commands are
    # treated as target interaction and must use the typed guard.
    is_source_command = _is_package_or_source_command(segment)
    url_hosts = _url_hosts(segment)
    if not is_source_command and url_hosts:
        return _message("URL detected in a non-package raw terminal command")

    # Public package/source URLs are host-local setup, not assessment traffic.
    # Keep numeric authorities conservative: a clone/install from an IP may be
    # an engagement target and must go through the typed guard.
    if (
        is_source_command
        and url_hosts
        and all(_is_known_source_host(host) for host in url_hosts)
        and not _IPV4_RE.search(segment)
    ):
        return None

    # ``init-engagement`` writes local workspace files and creates no network
    # traffic, so its scope host may be provided directly. Keep the exception
    # narrow: other guard subcommands still use the normal classifier, and
    # target values hidden behind shell expansion remain blocked.
    if _is_violin_init_command(segment):
        if _COMMAND_SUBSTITUTION_RE.search(segment) or _dynamic_init_host(segment):
            return _message(
                "dynamic init-engagement host detected; pass --host directly without "
                "shell or file indirection"
            )
        return None

    if executable not in _LOCAL_COMMANDS and _has_target_literal(segment):
        return _message("target host literal detected in the raw terminal command")

    if (
        executable in _SCRIPT_INTERPRETERS
        and _SUSPICIOUS_SCRIPT_RE.search(segment)
        and not _is_local_compilation_or_test(segment)
    ):
        return _message("assessment script detected in the raw terminal command")

    return None


def block_terminal_command(command: str) -> str | None:
    """Return a block message for clearly target-touching raw terminal calls.

    ``None`` means the command is host-local enough to remain available through
    the built-in terminal.  This is not a replacement for scope validation;
    it is the escape-hatch prevention layer that forces target work through the
    typed Violin tools.
    """
    if not isinstance(command, str) or not command.strip():
        return None

    for segment in _COMMAND_SPLIT_RE.split(command):
        if message := _block_terminal_segment(segment):
            return message
    return None


def _message(reason: str) -> str:
    return (
        "RAW TERMINAL TARGET EXECUTION BLOCKED by Violin: "
        f"{reason}. Use `violin_exec` for one command or `violin_exec_burst` "
        "for a bounded batch so scope, phase, PTT, hypotheses, history, "
        "evidence, and sync gates are enforced. The built-in terminal remains "
        "available for host-local preparation, tests, builds, and bookkeeping."
    )


__all__ = ["block_terminal_command"]
