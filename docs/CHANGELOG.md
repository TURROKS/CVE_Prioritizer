# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

<!-- insertion marker -->
## [v1.8.0](https://github.com/TURROKS/CVE_Prioritizer/releases/tag/v1.8.0) - 2024-11-03

<small>[Compare with v1.7.2](https://github.com/TURROKS/CVE_Prioritizer/compare/v1.7.2...v1.8.0)</small>

## [v1.7.2](https://github.com/TURROKS/CVE_Prioritizer/releases/tag/v1.7.2) - 2024-10-06

<small>[Compare with v1.6.1](https://github.com/TURROKS/CVE_Prioritizer/compare/v1.6.1...v1.7.2)</small>

### Added

- Added alternative kev source for vulncheck ([8dd2ca4](https://github.com/TURROKS/CVE_Prioritizer/commit/8dd2ca45a78b1b829d1235e1ea1b408ac573f008) by Mario Rojas).
- Added support for VulnCheck-CISA KEV ransomware checks ([1acd6fc](https://github.com/TURROKS/CVE_Prioritizer/commit/1acd6fcf2f104d9cdc1f6cd3ce9d4a6557509a69) by Mario Rojas).
- Added support for NIST-CISA KEV ransomware checks ([555012e](https://github.com/TURROKS/CVE_Prioritizer/commit/555012e2ac0f425b1eeaa2ce89aa4cb3f6c148e7) by Mario Rojas).
- Added Table of Contents and output image ([174f1ef](https://github.com/TURROKS/CVE_Prioritizer/commit/174f1efdcc1e816df9e38ef8acb7447a5a429c35) by Mario Rojas).
- Added SECURITY.md ([3c1a394](https://github.com/TURROKS/CVE_Prioritizer/commit/3c1a3940d9944f33e72c474c887a5f8540323095) by Mario Rojas).

### Fixed

- Fix ransomware issue with vulncheck kev ([a71c80f](https://github.com/TURROKS/CVE_Prioritizer/commit/a71c80fc18116a19cb5e68e5dc1c587ef5e7238d) by Mario Rojas).
- Fixed typo ([6544ea6](https://github.com/TURROKS/CVE_Prioritizer/commit/6544ea6da1737821cd2de0748d4c25f6d5415ddc) by Mario Rojas).
- Fixed error handling for CVEs in awaiting analysis status ([aca5f2a](https://github.com/TURROKS/CVE_Prioritizer/commit/aca5f2a4640d5e2d177267f5c1f3645460b2381b) by Mario Rojas).

### Removed

- Removed Jetbrains config files ([b80687d](https://github.com/TURROKS/CVE_Prioritizer/commit/b80687dc33657a3c43666c884b53295562f713fc) by Mario Rojas).

## [v1.6.1](https://github.com/TURROKS/CVE_Prioritizer/releases/tag/v1.6.1) - 2024-06-11

<small>[Compare with v1.4.0](https://github.com/TURROKS/CVE_Prioritizer/compare/v1.4.0...v1.6.1)</small>

### Added

- Added Changelog ([46637d5](https://github.com/TURROKS/CVE_Prioritizer/commit/46637d5ce252f9893451689312185008120caedf) by Mario Rojas).
- Added JSON output ([0595638](https://github.com/TURROKS/CVE_Prioritizer/commit/0595638b6fd48513417988e94b646a939c3c9454) by Mario Rojas).
- Added VulnCheck KEV support ([6e3e396](https://github.com/TURROKS/CVE_Prioritizer/commit/6e3e3965bc9e475a77f3b78ec8d163393feffa4e) by Mario Rojas).
- Added NVD++ as an alternative source of CVE data ([48be451](https://github.com/TURROKS/CVE_Prioritizer/commit/48be451e534cd26146ddb7d7924fcd3980845456) by Mario Rojas).
- Added vector string to outputs ([a76307d](https://github.com/TURROKS/CVE_Prioritizer/commit/a76307dd4f14ef225e3dd966edac25b07e95516b) by Mario Rojas).
- Added VulnCheck instructions ([440cac4](https://github.com/TURROKS/CVE_Prioritizer/commit/440cac4738f6a27a309dbb360f036740484a15f5) by Mario Rojas).
- Added option to save API keys into env file ([021d4f0](https://github.com/TURROKS/CVE_Prioritizer/commit/021d4f0191dc95142cac7c4dd9281f5d5726b6db) by Mario Rojas).
- Added -a, --api option to manually pass the api key ([f4f36c3](https://github.com/TURROKS/CVE_Prioritizer/commit/f4f36c31a57c937f06f91319fd7be0e2fe1cadf8) by Mario Rojas).
- Added --no-color output feature ([2871d2a](https://github.com/TURROKS/CVE_Prioritizer/commit/2871d2a33d366201fc87e4e64573dc194eca59eb) by Mario Rojas).
- Added pyproject.toml and updated version strings ([8cb8c8e](https://github.com/TURROKS/CVE_Prioritizer/commit/8cb8c8e3efc53495a92984c5b19a9508347a1858) by Mario Rojas).

### Fixed

- Fixed small typo on vulncheck_check function and standardized var names ([b4fdd98](https://github.com/TURROKS/CVE_Prioritizer/commit/b4fdd98bfc985aede5a1b83f54362c2c83a55138) by Mario Rojas).
- Fix invalid escape sequences by using raw strings ([679d275](https://github.com/TURROKS/CVE_Prioritizer/commit/679d275de42c23b756f0e7fcc1bc79fe9335eed7) by zevaryx).

## [v1.4.0](https://github.com/TURROKS/CVE_Prioritizer/releases/tag/v1.4.0) - 2023-12-10

<small>[Compare with v1.3.0](https://github.com/TURROKS/CVE_Prioritizer/compare/v1.3.0...v1.4.0)</small>

### Added

- Added Vendor + Product details ([2178de6](https://github.com/TURROKS/CVE_Prioritizer/commit/2178de63435afaa7aaf2104dffa029d63c0b34fe) by Mario Rojas).
- Added EPSS check ([9b31273](https://github.com/TURROKS/CVE_Prioritizer/commit/9b3127360213fcc48a9c1af6e4f345dfcfc67d33) by Mario Rojas).
- Added Error Codes ([23e93aa](https://github.com/TURROKS/CVE_Prioritizer/commit/23e93aaa2a1ab6d0d55bd1de2de2e31ef4677a8f) by Mario Rojas).
- Added missing instructions ([b0379f5](https://github.com/TURROKS/CVE_Prioritizer/commit/b0379f54d3a762abc653ed8f5ac9a1556e7038b1) by Mario Rojas).

### Fixed

- Fixed error with API Format for CVSS V2.0 CVEs ([baf0d0c](https://github.com/TURROKS/CVE_Prioritizer/commit/baf0d0c1291f34e7aff206c9c6ecf82007eb4414) by Mario Rojas).

## [v1.3.0](https://github.com/TURROKS/CVE_Prioritizer/releases/tag/v1.3.0) - 2023-06-03

<small>[Compare with first commit](https://github.com/TURROKS/CVE_Prioritizer/compare/fd145e73a8e55d469cbf9862a5c3af3a1f7c7dc2...v1.3.0)</small>

### Added

- Added throttling and threading semaphore ([d4513de](https://github.com/TURROKS/CVE_Prioritizer/commit/d4513de53406e79cf46e8e696498474746cee20d) by Mario Rojas).
- Added color coding ([1c3023a](https://github.com/TURROKS/CVE_Prioritizer/commit/1c3023a5e4ae093914aff4b3c3ba26f9d2a13fa8) by Mario Rojas).
- Added support for NIST API ([3aa8241](https://github.com/TURROKS/CVE_Prioritizer/commit/3aa8241911a12983f6635d29f3842c2d5b814680) by Mario Rojas).
- Added NVD API Notice ([f33ba81](https://github.com/TURROKS/CVE_Prioritizer/commit/f33ba8188853d0afdfddeb590112d43b876c10fe) by Mario Rojas).
- Added CVE Trends info ([3593b17](https://github.com/TURROKS/CVE_Prioritizer/commit/3593b17c70c1c4ac53e668090dbab44c54faedbf) by Mario Rojas).
- Added CVE Trends demo option ([dfcf6cd](https://github.com/TURROKS/CVE_Prioritizer/commit/dfcf6cdbf262ce99a8320f1cb3003c84a1e9101e) by Mario Rojas).
- Added input validation and normalization ([365b7be](https://github.com/TURROKS/CVE_Prioritizer/commit/365b7beb35373ee27def375071725057d27841ae) by Mario Rojas).
- Added CVSS Version to results ([6df7cde](https://github.com/TURROKS/CVE_Prioritizer/commit/6df7cde2dfa7d0fe12f16e79f31ac67d2c722136) by Mario Rojas).
- Added function details ([f404c45](https://github.com/TURROKS/CVE_Prioritizer/commit/f404c45d4d7ba43cef7b75b8d2ededa391bb768d) by Mario Rojas).
- Added README ([800d93a](https://github.com/TURROKS/CVE_Prioritizer/commit/800d93a0174b8e27d36252a47d4c4af0029b5025) by Mario Rojas).
- Added verbose output option ([81602f3](https://github.com/TURROKS/CVE_Prioritizer/commit/81602f38a108fb52cdbea3f3b2e9825eb9b7c4aa) by Mario Rojas).
- Added argparse options ([6ffa981](https://github.com/TURROKS/CVE_Prioritizer/commit/6ffa9810e1389f9d605c5e0f702d7cf69b4a910d) by Mario Rojas).
- Added f-string formatting ([e31d829](https://github.com/TURROKS/CVE_Prioritizer/commit/e31d829569f84a21213e580a1288d3ada79c5b9d) by Mario Rojas).
- Added support for Threading ([d0e8981](https://github.com/TURROKS/CVE_Prioritizer/commit/d0e898191588765d84f4f892227e09d14986fbde) by Mario Rojas).
- Added priority thresholds ([9c20a76](https://github.com/TURROKS/CVE_Prioritizer/commit/9c20a76cfc41df13f767d9ce93266e6e952ddd82) by Mario Rojas).

### Removed

- Removed .env from gitignore ([1878f8d](https://github.com/TURROKS/CVE_Prioritizer/commit/1878f8d7cb01ffde43bfb8b3021d4142329d9c1f) by Mario Rojas).
- Removed redundant variables ([eb4fe45](https://github.com/TURROKS/CVE_Prioritizer/commit/eb4fe45942732b5c77d5b32f43c7f373560fd06d) by Mario Rojas).

