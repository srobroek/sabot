# Changelog

## Unreleased


### ⚠ BREAKING CHANGES

* **sabot:** the `scout` agent is now `sabot-scout` ([#53](https://github.com/srobroek/sabot/issues/53)). It collided with omp's bundled `scout`, and a user plugin outranks a bundled agent, so every `scout` invocation silently got sabot's `opus` recon agent rather than the bundled cheap recon leaf. A Brief, formula, or prompt naming `scout` or `sabot:scout` now resolves nothing; use `sabot-scout` and `sabot:sabot-scout`. `references/scout-brief.md` keeps its path.

### Refactors

* **sabot:** rename the scout agent out of its collision with omp's bundled scout ([#53](https://github.com/srobroek/sabot/issues/53))

## [0.5.2](https://github.com/srobroek/sabot/compare/v0.5.1...v0.5.2) (2026-08-22)


### Bug Fixes

* **sabot:** document that operational state goes through bd set-state ([#51](https://github.com/srobroek/sabot/issues/51)) ([f8e18fb](https://github.com/srobroek/sabot/commit/f8e18fb2cee37f8b90d410cd473941622cc99ca7))

## [0.5.1](https://github.com/srobroek/sabot/compare/v0.5.0...v0.5.1) (2026-08-22)


### Bug Fixes

* **sabot:** report a harness stopped by the clock, and warn that the poured formula goes stale ([#48](https://github.com/srobroek/sabot/issues/48)) ([e3bdba5](https://github.com/srobroek/sabot/commit/e3bdba5eb2300fc37288b500d8f73c6886c96d10))

## [0.5.0](https://github.com/srobroek/sabot/compare/v0.4.0...v0.5.0) (2026-08-22)


### ⚠ BREAKING CHANGES

* **sabot:** scripts/pour-campaign.sh is removed. Pour with `bd mol pour` directly and resolve gates with `bd gate resolve`.

### Bug Fixes

* **sabot:** close the four fail-opens a self-audit run found ([#47](https://github.com/srobroek/sabot/issues/47)) ([29aeb64](https://github.com/srobroek/sabot/commit/29aeb64463b71cae06fe465091e9731df604177c))
* **sabot:** retract the inert-gate finding, and drop the script built on it ([#45](https://github.com/srobroek/sabot/issues/45)) ([884244e](https://github.com/srobroek/sabot/commit/884244efb41eb93880c30f9fb49d9533db2b3108))

## [0.4.0](https://github.com/srobroek/sabot/compare/v0.3.2...v0.4.0) (2026-08-22)


### ⚠ BREAKING CHANGES

* **sabot:** every step number in the sabot skill has changed. A Brief, prompt, or script citing an old number now points at the wrong step.

### Features

* **sabot:** pour the workflow as a molecule, and flatten the step numbers ([#41](https://github.com/srobroek/sabot/issues/41)) ([65e2013](https://github.com/srobroek/sabot/commit/65e2013792c8ffe54e996053c897dc20e5c61137))

## [0.3.2](https://github.com/srobroek/sabot/compare/v0.3.1...v0.3.2) (2026-08-21)


### Documentation

* **sabot:** stop the report stage gating on the gaps it exists to report ([#39](https://github.com/srobroek/sabot/issues/39)) ([38dc354](https://github.com/srobroek/sabot/commit/38dc354b16185a1d19332e54656f9c3868d59c0f))

## [0.3.1](https://github.com/srobroek/sabot/compare/v0.3.0...v0.3.1) (2026-08-21)


### Bug Fixes

* **sabot:** separate an audit's beads from the project's backlog ([#37](https://github.com/srobroek/sabot/issues/37)) ([227d16f](https://github.com/srobroek/sabot/commit/227d16fee337023b53d7d806858add8174b101f6))

## [0.3.0](https://github.com/srobroek/sabot/compare/v0.2.0...v0.3.0) (2026-08-21)


### Features

* choose whether findings become patches or tickets, and stop reporting unrun checks as clean ([#32](https://github.com/srobroek/sabot/issues/32)) ([d0fdfec](https://github.com/srobroek/sabot/commit/d0fdfec8ad3ba7cab23a18b480a01b194f2ea54b))


### Bug Fixes

* release a claimed wisp, and name the scanners a coverage record claims ([#36](https://github.com/srobroek/sabot/issues/36)) ([5bcd7cd](https://github.com/srobroek/sabot/commit/5bcd7cd0cf8a8cd541caa55ca0f1522ecb83075f))
* route a broken harness back, and keep the reproduce command ([#34](https://github.com/srobroek/sabot/issues/34)) ([167a168](https://github.com/srobroek/sabot/commit/167a16849b0b4d841e6e5c4af063f09492e302cc))
* **sabot:** require the control a harness result is tiered against ([#33](https://github.com/srobroek/sabot/issues/33)) ([d80f18f](https://github.com/srobroek/sabot/commit/d80f18f5cd7e960465e705ea0a78da07e2294f68))
* total the coverage numbers a campaign is required to report ([#35](https://github.com/srobroek/sabot/issues/35)) ([efa00da](https://github.com/srobroek/sabot/commit/efa00daacb0c06fa02a1130cae4b123556ce666d))


### Documentation

* drop the orphaned separators the last README edit left in the diagram ([#30](https://github.com/srobroek/sabot/issues/30)) ([86605b5](https://github.com/srobroek/sabot/commit/86605b54d5654d37df688047ba8b7f4d98e5c9ce))

## [0.2.0](https://github.com/srobroek/sabot/compare/v0.1.0...v0.2.0) (2026-08-19)


### Features

* **sabot:** bake base-extras, and add the rust-extras, heavy, scanners, and generator surfaces ([#29](https://github.com/srobroek/sabot/issues/29)) ([792be13](https://github.com/srobroek/sabot/commit/792be139dff79699496c0466f1ac4bfd9fcef5ca))


### Bug Fixes

* **sabot/base:** symlink rg to ripgrep so the tool probe answers ([0949cf1](https://github.com/srobroek/sabot/commit/0949cf193bfc6c8e1e3dac43d0a02586c03b2fb2))
* **sabot:** bake offline vuln DBs, rule packs, and fuzz deps into surface images ([#25](https://github.com/srobroek/sabot/issues/25)) ([d6dea76](https://github.com/srobroek/sabot/commit/d6dea76f35d1f803e0ab8893fefc28878d6c6c26))
* **sabot:** first-class writable-source build recipe (--copy-src, --scratch) ([#23](https://github.com/srobroek/sabot/issues/23)) ([ac109a8](https://github.com/srobroek/sabot/commit/ac109a8c627cbbbc61fb0af5f8cc66a05d12ca32))
* **sabot:** make the container execution path actually run a cargo campaign ([#21](https://github.com/srobroek/sabot/issues/21)) ([164855e](https://github.com/srobroek/sabot/commit/164855efb925dd53ba363dcd674ce926519d9ab2))
* **sabot:** make the python and node surfaces ship working fuzzers (bs-156) ([#27](https://github.com/srobroek/sabot/issues/27)) ([7e34155](https://github.com/srobroek/sabot/commit/7e34155f7615e19c162394d96924a595cad96ab8))


### Documentation

* **sabot:** correct detect-stacks.py --json drift to real interface ([#22](https://github.com/srobroek/sabot/issues/22)) ([eb97145](https://github.com/srobroek/sabot/commit/eb971454839e59cd85284cb375e0bd398fa7c0a1))
* **sabot:** tool coverage matrix — 57 tools, offline requirement, bake status ([#24](https://github.com/srobroek/sabot/issues/24)) ([ad8ff21](https://github.com/srobroek/sabot/commit/ad8ff215105bcca32d4023a0dfae46811a6516a0))

## [0.1.0](https://github.com/srobroek/break-stuff/compare/sabot-marketplace--v0.1.0...sabot-marketplace--v0.1.0) (2026-08-17)


### ⚠ BREAKING CHANGES

* rename break-stuff to sabot (package/repo) + sabotage (skill) ([#11](https://github.com/srobroek/break-stuff/issues/11))

### Features

* **break-stuff:** interview-by-default, agentic-code recon, delegate provisioning ([#10](https://github.com/srobroek/break-stuff/issues/10)) ([dae4b75](https://github.com/srobroek/break-stuff/commit/dae4b755b99caca45bb8e9b3d39c4b8c896c48d1))
* generate both marketplaces + release-please, add README ([e65b95d](https://github.com/srobroek/break-stuff/commit/e65b95dade30fd8c0fe7960c8f26ecfdd727cb0f))


### Refactors

* rename break-stuff to sabot (package/repo) + sabotage (skill) ([#11](https://github.com/srobroek/break-stuff/issues/11)) ([6eede11](https://github.com/srobroek/break-stuff/commit/6eede11ee046d646d39855f30442d4c46c9af64c))


### Documentation

* real README — usage, agent chain, correct dual-marketplace install ([638a8ae](https://github.com/srobroek/break-stuff/commit/638a8ae2fc453df2f2a6da018872bda659fedf91))
