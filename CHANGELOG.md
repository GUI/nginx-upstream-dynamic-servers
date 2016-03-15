# nginx-upstream-dynamic-servers Change Log

## [0.4.0] - 2016-03-14
### Changed
- New API using the standard nginx `server` syntax (instead of `dynamic_server`) and a `resolve` parameter. (Thanks to @wandenberg)
- Improved memory usage. (Thanks to @wandenberg)

## [0.3.0] - 2016-03-07
### Added
- Compatibility with nginx 1.6 and 1.9. (Thanks to @wandenberg)

## [0.2.0] - 2016-03-02
### Added
- Compatibility with nginx 1.8 and 1.7. (Thanks to @wandenberg)

### Fixed
- Fix segfault during repeated nginx reloads. (Thanks to @wandenberg)

## 0.1.0 - 2014-11-29
### Added
- Initial release.

[0.4.0]: https://github.com/GUI/nginx-upstream-dynamic-servers/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/GUI/nginx-upstream-dynamic-servers/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/GUI/nginx-upstream-dynamic-servers/compare/v0.1.0...v0.2.0
