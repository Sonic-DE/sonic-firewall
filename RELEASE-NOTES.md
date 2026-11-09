# Sonic Firewall Release Notes

Sonic Firewall lets you turn your computer's firewall on or off and manage its rules from SonicDE's settings.

## 6.8.2 (2026-11-10)

- The firewall settings now work on systems without systemd: OpenRC, runit, s6, dinit, sysvinit and BSD rc.
- The firewall log view now works without the systemd journal, and shows source ports and times correctly.
- Turning the firewall off now also stops it starting at boot when it was set up in a runlevel other than the default one.
- If the firewall can't be set to start automatically, you now see a warning instead of nothing.
- Turning the firewall on or off now asks for your password only once.
- Behind the scenes: logging moved to SonicDE's logging system.

## 6.8.0 (2026-10-20)

- Behind the scenes: version update.

## 6.7.5 (2026-09-12)

- Behind the scenes: version update.

## 6.7.4 (2026-08-04)

No SonicDE-specific changes in this release; it brings the package up to date with upstream.

## 6.7.3 (2026-07-14)

- Behind the scenes: restored the code formatting settings and added support for developers' code-navigation tools.
