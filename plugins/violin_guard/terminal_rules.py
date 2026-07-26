"""Terminal command policy rule sets and pattern definitions."""

from __future__ import annotations

import re

_SHELL_WRAPPERS = frozenset({"bash", "cmd", "fish", "powershell", "pwsh", "sh", "zsh"})
_SCRIPT_INTERPRETERS = _SHELL_WRAPPERS | {
    "node",
    "perl",
    "python",
    "python3",
    "ruby",
}
_PACKAGE_OR_SOURCE_COMMANDS = frozenset(
    {"cargo", "curl", "fetch", "git", "go", "npm", "pip", "pip3", "pnpm", "uv", "wget", "yarn"}
)
_LOCAL_COMMANDS = frozenset(
    {
        "awk",
        "cat",
        "cmake",
        "cp",
        "date",
        "diff",
        "dir",
        "echo",
        "false",
        "find",
        "grep",
        "head",
        "hermes",
        "ls",
        "make",
        "mkdir",
        "mv",
        "printf",
        "pwd",
        "pytest",
        "rg",
        "ripgrep",
        "rm",
        "sed",
        "sort",
        "tail",
        "touch",
        "true",
        "uniq",
        "wc",
    }
)
_COMMAND_SPLIT_RE = re.compile(r"&&|\|\||[;|\n]")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\b(?:https?|ftp|wss?|file)://[^\s'\"<>]+", re.IGNORECASE)
_KNOWN_SOURCE_HOSTS = frozenset(
    {
        "bitbucket.org",
        "crates.io",
        "files.pythonhosted.org",
        "gist.github.com",
        "gist.githubusercontent.com",
        "github.com",
        "gitlab.com",
        "go.dev",
        "objects.githubusercontent.com",
        "proxy.golang.org",
        "pypi.org",
        "raw.githubusercontent.com",
        "registry.npmjs.org",
    }
)
_NETWORK_PATH_RE = re.compile(r"/(?:dev/)?(?:tcp|udp)/", re.IGNORECASE)
_NETWORK_MODULE_RE = re.compile(
    r"\b(?:http\.server|requests|httpx|urllib(?:\.request)?|socket(?:server)?|scapy|paramiko)\b",
    re.IGNORECASE,
)
_COMMAND_SUBSTITUTION_RE = re.compile(r"\$\(|`")
_SUSPICIOUS_SCRIPT_RE = re.compile(
    r"\b(?:attack|exploit|fuzz|payload|poc|probe|recon|scan|scanner)\b",
    re.IGNORECASE,
)
_LOCAL_FILE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyw",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".js",
        ".mjs",
        ".cjs",
        ".rb",
        ".pl",
        ".log",
        ".txt",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".csv",
        ".tsv",
        ".out",
        ".err",
        ".dat",
        ".conf",
        ".cfg",
        ".ini",
        ".md",
    }
)
