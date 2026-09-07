"""Deployed systemd units must stay valid: dead units page nobody.

Every ``interceptor <subcommand> --flag`` token in an ExecStart line is
checked against the real CLI parser, and every timer is linked to a service
that exists. A typo'd flag would otherwise fail silently at 3am instead of
in CI.
"""

from __future__ import annotations

import configparser
import re
from pathlib import Path

from interceptor.cli import build_parser

UNITS = Path(__file__).resolve().parent.parent / "deploy" / "systemd"

COMMAND_RE = re.compile(r"interceptor\s+([a-z][a-z-]*)")
FLAG_RE = re.compile(r"--[a-z][a-z-]*")


def _units(suffix: str) -> list[Path]:
    return sorted(UNITS.glob(f"*{suffix}"))


def _subparsers():
    parser = build_parser()
    for action in parser._actions:
        if action.__class__.__name__ == "_SubParsersAction":
            return action.choices
    raise AssertionError("no subparsers in CLI parser")


def test_services_reference_real_commands_and_flags():
    choices = _subparsers()
    services = _units(".service")
    assert len(services) >= 3
    for unit in services:
        # strict=False: systemd allows repeated directives (Environment=).
        config = configparser.ConfigParser(interpolation=None, strict=False)
        config.read(unit)
        assert "Unit" in config and "Service" in config, unit.name
        assert config["Service"]["Type"] == "oneshot", unit.name
        line = config["Service"]["ExecStart"]
        matches = list(COMMAND_RE.finditer(line))
        assert matches, f"{unit.name} invokes no interceptor command"
        for index, match in enumerate(matches):
            subcommand = match.group(1)
            assert subcommand in choices, f"{unit.name}: unknown subcommand {subcommand}"
            segment = line[
                match.start() : matches[index + 1].start()
                if index + 1 < len(matches)
                else len(line)
            ]
            valid_flags = set()
            for action in choices[subcommand]._actions:
                valid_flags.update(action.option_strings)
            for flag in FLAG_RE.findall(segment):
                assert flag in valid_flags, f"{unit.name}: unknown flag {flag}"


def test_timers_link_to_existing_services():
    timers = _units(".timer")
    assert len(timers) >= 2
    for timer in timers:
        config = configparser.ConfigParser(interpolation=None, strict=False)
        config.read(timer)
        assert "Timer" in config, timer.name
        assert "OnCalendar" in config["Timer"], timer.name
        service = UNITS / config["Timer"]["Unit"]
        assert service.exists(), f"{timer.name} points at missing {service.name}"
