# Changelog

All notable changes to `security-advisories-health-check` will be documented in this file.

## 1.4.0 - 2026-10-26

### Added

- Ignore individual Packagist security advisory IDs with ignoreAdvisoryId() or ignoredAdvisoryIds(), while continuing to report other advisories for the same package. Thanks to @frasermurraysco in https://github.com/spatie/security-advisories-health-check/pull/40.
- Apply advisory exclusions after fetching or reading cached results; no cache key changes are required.
- Add regression coverage for partial, complete, and multiple advisory exclusions.

No breaking changes. Existing package-wide exclusions continue to work.

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/1.3.3...1.4.0

## 1.3.3 - 2026-10-17

Reduce the size of stored security-advisory results by retaining actionable fields and the affected version range matching the installed package.

Includes correct handling of Composer `|` and `||` constraints and customizable metadata field selection.

Compatibility note: result metadata no longer contains the full Packagist advisory record. Subclasses can add omitted fields back through the protected `$advisoryFieldsInMeta` property.

### What's Changed

* Store a slimmer advisory record in the result meta by @mattiasgeniar in https://github.com/spatie/security-advisories-health-check/pull/39

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/1.3.2...1.3.3

## 1.3.2 - 2026-08-07

### What's Changed

* Bump dependabot/fetch-metadata from 2.4.0 to 2.5.0 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/34
* Bump actions/checkout from 2 to 6 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/33
* Bump stefanzweifel/git-auto-commit-action from 6 to 7 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/32
* Bump dependabot/fetch-metadata from 2.5.0 to 3.0.0 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/35
* Bump dependabot/fetch-metadata from 3.0.0 to 3.1.0 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/36
* Bump actions/checkout from 6 to 7 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/37
* Cache advisories as a plain array to support serializable_classes=false by @arnevanhoorn in https://github.com/spatie/security-advisories-health-check/pull/38

### New Contributors

* @arnevanhoorn made their first contribution in https://github.com/spatie/security-advisories-health-check/pull/38

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/1.3.1...1.3.2

## 1.3.1 - 2025-10-07

### What's Changed

* Bugfix for registering checks in register() with support for registering in boot() by @mattiasgeniar in https://github.com/spatie/security-advisories-health-check/pull/31

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/1.3.0...1.3.1

## 1.3.0 - 2025-09-28

### What's Changed

* Bump dependabot/fetch-metadata from 1.6.0 to 2.1.0 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/20
* Bump dependabot/fetch-metadata from 2.1.0 to 2.2.0 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/22
* Bump dependabot/fetch-metadata from 2.2.0 to 2.3.0 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/23
* Bump dependabot/fetch-metadata from 2.3.0 to 2.4.0 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/24
* Update issue template by @AlexVanderbist in https://github.com/spatie/security-advisories-health-check/pull/27
* Allow opt-in caching of the security check by @mattiasgeniar in https://github.com/spatie/security-advisories-health-check/pull/28
* Add caching by @freekmurze in https://github.com/spatie/security-advisories-health-check/pull/29
* Bump stefanzweifel/git-auto-commit-action from 4 to 6 by @dependabot[bot] in https://github.com/spatie/security-advisories-health-check/pull/25

### New Contributors

* @AlexVanderbist made their first contribution in https://github.com/spatie/security-advisories-health-check/pull/27
* @mattiasgeniar made their first contribution in https://github.com/spatie/security-advisories-health-check/pull/28
* @freekmurze made their first contribution in https://github.com/spatie/security-advisories-health-check/pull/29

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/1.2.1...1.3.0

## 1.2.1 - 2024-06-05

### What's Changed

* Ignore Packagist connection errors by @emaadali in https://github.com/spatie/security-advisories-health-check/pull/21

### New Contributors

* @emaadali made their first contribution in https://github.com/spatie/security-advisories-health-check/pull/21

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/1.2.0...1.2.1

## 1.2.0 - 2024-03-18

### What's Changed

* Update some dependencies by @kudashevs in https://github.com/spatie/security-advisories-health-check/pull/18

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/1.1.0...1.2.0

## 1.1.0 - 2023-08-25

- retry calling Packagist to avoid false positives

## 0.0.2 - 2022-08-03

**Full Changelog**: https://github.com/spatie/security-advisories-health-check/compare/0.0.1...0.0.2

## 0.0.1 - 2022-08-03

- experimental release

## 1.0.2 - 2021-12-13

- fix class name

## 1.0.1 - 2021-12-13

- fix installation

## 1.0.0 - 2021-12-13

- initial release
