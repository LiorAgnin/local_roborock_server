# Roborock Local Server

A private stand-in for the Roborock cloud: the HTTPS and MQTT services a Roborock vacuum and app expect, run on the owner's own network.

## Lineage

**Upstream**:
The original Python project, `Python-roborock/local_roborock_server`, that this repository forked from and keeps following for behaviour changes.
_Avoid_: origin, main repo

**Reference server**:
The Python implementation, kept as the authority on correct behaviour while a replacement is built against it.
_Avoid_: old server, legacy server

**Conformance suite**:
The black-box tests that exercise the stack only through its HTTPS and MQTT surfaces, so the same tests judge any implementation.
_Avoid_: contract tests (a contract test is one member of the suite), integration tests

**Behaviour port**:
Carrying one Upstream behaviour change into the replacement, captured first as a Conformance suite case.
_Avoid_: backport, sync, cherry-pick

**Drop-in**:
A replacement a user can swap in with their existing configuration and without re-onboarding any vacuum.
_Avoid_: compatible, seamless
