# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.3.0] - 2026-07-11

### Features
- Capped high-value-first coin selection + cap-aware consolidation (#1)

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

## [0.2.0] - 2026-04-21

### Features
- Migrate encryption to dig-keystore (v0.2.0)

## [0.1.0] - 2026-04-12

### Features
- Add wallet

### Bug Fixes
- Resolve fmt and clippy warnings, add comprehensive README- Use crates.io chia-query dependency instead of path


