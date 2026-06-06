# Changelog

## [1.5.0](https://github.com/batonogov/xray-health-exporter/compare/v1.4.0...v1.5.0) (2026-06-06)


### Features

* add DI interfaces (HealthChecker, MetricsUpdater) on top of current main ([#98](https://github.com/batonogov/xray-health-exporter/issues/98)) ([11337fd](https://github.com/batonogov/xray-health-exporter/commit/11337fdfcf373f7a2038c51b52c4de30c4da0241))
* add exporter internal metrics (build_info, uptime, reload counters) ([#104](https://github.com/batonogov/xray-health-exporter/issues/104)) ([384c46e](https://github.com/batonogov/xray-health-exporter/commit/384c46e4b9121b5d9e5b6e4416acab622a4a5224))
* add Grafana dashboard for tunnel monitoring ([#97](https://github.com/batonogov/xray-health-exporter/issues/97)) ([c985c04](https://github.com/batonogov/xray-health-exporter/commit/c985c049bfb17807db76da297b3e79c2f9f888ff))
* add histogram metric for latency percentile queries ([#102](https://github.com/batonogov/xray-health-exporter/issues/102)) ([54fcea3](https://github.com/batonogov/xray-health-exporter/commit/54fcea338a0328a7374010b4dd2002b6b990b545)), closes [#29](https://github.com/batonogov/xray-health-exporter/issues/29)
* add xray_tunnel_error_total metric with error categorization ([#100](https://github.com/batonogov/xray-health-exporter/issues/100)) ([03cb6a0](https://github.com/batonogov/xray-health-exporter/commit/03cb6a05fda51253e61b29d94cd6bdc7d30bfc77))
* exponential backoff for repeated tunnel check failures ([#103](https://github.com/batonogov/xray-health-exporter/issues/103)) ([609c693](https://github.com/batonogov/xray-health-exporter/commit/609c69327fcd3ec5f3e3b407ca6694726eb01b1e))
* support custom SOCKS ports in tunnel configuration ([#99](https://github.com/batonogov/xray-health-exporter/issues/99)) ([aed219e](https://github.com/batonogov/xray-health-exporter/commit/aed219efb42fff6e72bb5d593a7846e31fb6fb9e))


### Bug Fixes

* resolve rebase conflicts and address review feedback ([#101](https://github.com/batonogov/xray-health-exporter/issues/101)) ([454af73](https://github.com/batonogov/xray-health-exporter/commit/454af73c13eb7e515c472e65f880de54402a2478))
* stabilize TestMetricsEndpoint_IncludesHistogram flaky test ([18a4eeb](https://github.com/batonogov/xray-health-exporter/commit/18a4eeb391072c19bae5c0451eee685a01c24ee9))


### Dependencies

* **deps:** bump golang in the docker-dependencies group ([#107](https://github.com/batonogov/xray-health-exporter/issues/107)) ([4c7c423](https://github.com/batonogov/xray-health-exporter/commit/4c7c423f8c39d318ed1ca04894839131907f8a6b))

## [1.4.0](https://github.com/batonogov/xray-health-exporter/compare/v1.3.0...v1.4.0) (2026-05-26)


### Features

* staggered initial checks to prevent thundering herd ([#95](https://github.com/batonogov/xray-health-exporter/issues/95)) ([de20435](https://github.com/batonogov/xray-health-exporter/commit/de20435e1f5e8e4c718ff651de67340df964650a))


### Bug Fixes

* gRPC+Reality connection reset by setting authority fallback ([#93](https://github.com/batonogov/xray-health-exporter/issues/93)) ([0d60660](https://github.com/batonogov/xray-health-exporter/commit/0d606607ed2112a9b2a69736c7e3e96eca97ce08))

## [1.3.0](https://github.com/batonogov/xray-health-exporter/compare/v1.2.3...v1.3.0) (2026-05-26)


### Features

* structured logging (slog) ([#89](https://github.com/batonogov/xray-health-exporter/issues/89)) ([c4a8940](https://github.com/batonogov/xray-health-exporter/commit/c4a8940e87e1f4ebc32078092132bad95ccba2e9))
* support gRPC transport in VLESS URL parsing ([#91](https://github.com/batonogov/xray-health-exporter/issues/91)) ([5b7b06d](https://github.com/batonogov/xray-health-exporter/commit/5b7b06d58b825bbe08ef0edd6cfc4f0352d3556e))


### Dependencies

* **deps:** bump the go-dependencies group with 2 updates ([#86](https://github.com/batonogov/xray-health-exporter/issues/86)) ([0a8bb09](https://github.com/batonogov/xray-health-exporter/commit/0a8bb090a002e2c99669f0c77dc9c59cee3fee91))

## [1.2.3](https://github.com/batonogov/xray-health-exporter/compare/v1.2.2...v1.2.3) (2026-05-13)


### Dependencies

* **deps:** bump docker/setup-qemu-action in the github-actions group ([#83](https://github.com/batonogov/xray-health-exporter/issues/83)) ([732fe24](https://github.com/batonogov/xray-health-exporter/commit/732fe24e8a8b52874328323e767943eebb537264))
* **deps:** bump golang in the docker-dependencies group ([#85](https://github.com/batonogov/xray-health-exporter/issues/85)) ([1bfaf5d](https://github.com/batonogov/xray-health-exporter/commit/1bfaf5de9d12aa387ff799243f0b4db2b4c5d490))

## [1.2.2](https://github.com/batonogov/xray-health-exporter/compare/v1.2.1...v1.2.2) (2026-05-05)


### Bug Fixes

* publish versioned Docker aliases with v prefix ([#81](https://github.com/batonogov/xray-health-exporter/issues/81)) ([fe890ac](https://github.com/batonogov/xray-health-exporter/commit/fe890aca0e20e68ce31f410a17fcaa104da52516))

## [1.2.1](https://github.com/batonogov/xray-health-exporter/compare/v1.2.0...v1.2.1) (2026-05-04)


### Dependencies

* **deps:** bump github.com/fsnotify/fsnotify ([#77](https://github.com/batonogov/xray-health-exporter/issues/77)) ([5d85987](https://github.com/batonogov/xray-health-exporter/commit/5d85987d4039faf45305e8e2cc9d05198f14d7cb))

## [1.2.0](https://github.com/batonogov/xray-health-exporter/compare/v1.1.2...v1.2.0) (2026-05-04)


### Features

* add Kubernetes leader election for HA deployments ([#72](https://github.com/batonogov/xray-health-exporter/issues/72)) ([a9abe80](https://github.com/batonogov/xray-health-exporter/commit/a9abe80744647e2a5a36c6638e18e69ce07fa584))

## [1.1.2](https://github.com/batonogov/xray-health-exporter/compare/v1.1.1...v1.1.2) (2026-04-10)


### Bug Fixes

* use go release-type for release-please to include changelog in release body ([#64](https://github.com/batonogov/xray-health-exporter/issues/64)) ([7e3e535](https://github.com/batonogov/xray-health-exporter/commit/7e3e5352435ce41831c1c6a368177e6626070980))

## [1.1.1](https://github.com/batonogov/xray-health-exporter/compare/v1.1.0...v1.1.1) (2026-04-10)


### Bug Fixes

* use release event trigger instead of tag push for release workflow ([#62](https://github.com/batonogov/xray-health-exporter/issues/62)) ([c63979f](https://github.com/batonogov/xray-health-exporter/commit/c63979f9edff016be8e7c375378e39c1d6ad593d))

## [1.1.0](https://github.com/batonogov/xray-health-exporter/compare/v1.0.1...v1.1.0) (2026-04-10)


### Features

* xray_config_file, all protocols, subscription URL support ([#60](https://github.com/batonogov/xray-health-exporter/issues/60)) ([361e199](https://github.com/batonogov/xray-health-exporter/commit/361e1998082b174f99d85cd7f990f2ff7c4ee858))
