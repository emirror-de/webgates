# 📜 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-08-15
### 📝 Other Changes
- Added RELEASE_NOTES.md [060a61e](https://github.com/emirror-de/webgates/commit/060a61e0cfc272f79cd00bc16a11daeb2210aede)

- Bumped version numbers of all crates, set workspace version to 1.2.0 [9da006d](https://github.com/emirror-de/webgates/commit/9da006d18cf4d455949308edd3b67c525c15bc91)

- Added missing use statements in doc-tests [f61dd12](https://github.com/emirror-de/webgates/commit/f61dd12f136783c345b45a89543c50945f9788d3)

- TTL config retrieval at wrong code position [caa92e5](https://github.com/emirror-de/webgates/commit/caa92e51af7c20e43f4e70438bbf374490fa269a)

- Align cookie expiration with typed token metadata [61fd71a](https://github.com/emirror-de/webgates/commit/61fd71a987c190272e60b6652e5470f59271152a)

- Removed all Cargo.lock files except the root one, added this to .gitignore [7585523](https://github.com/emirror-de/webgates/commit/7585523251fbaf35a8d03a85cf16d9a43adb7b2a)

- Merge pull request #4 from emirror-de/dependabot/cargo/jsonwebtoken-11.0.0 chore(deps): bump jsonwebtoken from 10.4.0 to 11.0.0 [f7cb8f6](https://github.com/emirror-de/webgates/commit/f7cb8f6f02b34ae04400a527c3f2585b555a189d)

- Merge conflicts [192d86a](https://github.com/emirror-de/webgates/commit/192d86a6ff7b42085939c69bbd93f3c2211e7f33)

- Merge pull request #7 from emirror-de/dependabot/cargo/rand-0.10.2 chore(deps): bump rand from 0.9.5 to 0.10.2 [e06b905](https://github.com/emirror-de/webgates/commit/e06b905eddd884e463477039e130b1a254c1c9af)

- Updated changed import of rand [e33f89e](https://github.com/emirror-de/webgates/commit/e33f89e354c72c85654d5b183218f4fb978a437d)

- Merge conflict [c6ba000](https://github.com/emirror-de/webgates/commit/c6ba00050292dd22bab3aa214ca63adfb06ce9ea)

- Clippy lint [1410d51](https://github.com/emirror-de/webgates/commit/1410d51b7f1241ec5247ce2d54660d49d8949975)

- Updated to new jsonwebtoken syntax [e0e3328](https://github.com/emirror-de/webgates/commit/e0e33288b4367c83a18999014d55177aacaafe76)

- Removed unused imports in tests [ae53903](https://github.com/emirror-de/webgates/commit/ae53903ba9926279138b1c317df5f63e8fc1de6c)

- Merge pull request #5 from emirror-de/dependabot/cargo/p384-0.14.0 chore(deps): bump p384 from 0.13.1 to 0.14.0 [8cba542](https://github.com/emirror-de/webgates/commit/8cba542a9ef067d49279ec8c831d7422309b5237)

- Updated to latest API of p384 [4bc2028](https://github.com/emirror-de/webgates/commit/4bc2028e17135a37f53bf8894c7f436a338b85d8)

- Merge pull request #3 from emirror-de/dependabot/cargo/strum-0.28.0 chore(deps): bump strum from 0.27.2 to 0.28.0 [25af1d0](https://github.com/emirror-de/webgates/commit/25af1d0c541d286fb7b1e7672160242246fff4b8)

- Merge pull request #6 from emirror-de/dependabot/cargo/sha2-0.11.0 chore(deps): bump sha2 from 0.10.9 to 0.11.0 [4c21f80](https://github.com/emirror-de/webgates/commit/4c21f80b49c219e166453a0dffaa26f9d6ed0c1a)

- Added initial dependabot.yml [63c3030](https://github.com/emirror-de/webgates/commit/63c30304822f13120bde05a426a872a98cb15f8b)



### 🚲 Miscellaneous
- Bump rand from 0.9.5 to 0.10.2 Bumps [rand](https://github.com/rust-random/rand) from 0.9.5 to 0.10.2. - [Release notes](https://github.com/rust-random/rand/releases) - [Changelog](https://github.com/rust-random/rand/blob/master/CHANGELOG.md) - [Commits](https://github.com/rust-random/rand/compare/0.9.5...0.10.2) --- updated-dependencies: - dependency-name: rand dependency-version: 0.10.2 dependency-type: direct:production update-type: version-update:semver-minor ... Signed-off-by: dependabot[bot] <support@github.com> *(deps)*  [7c4da19](https://github.com/emirror-de/webgates/commit/7c4da190d170e757f59d2c854c25d41b58bddaeb)

- Bump jsonwebtoken from 10.4.0 to 11.0.0 Bumps [jsonwebtoken](https://github.com/Keats/jsonwebtoken) from 10.4.0 to 11.0.0. - [Changelog](https://github.com/Keats/jsonwebtoken/blob/master/CHANGELOG.md) - [Commits](https://github.com/Keats/jsonwebtoken/compare/v10.4.0...v11.0.0) --- updated-dependencies: - dependency-name: jsonwebtoken dependency-version: 11.0.0 dependency-type: direct:production update-type: version-update:semver-major ... Signed-off-by: dependabot[bot] <support@github.com> *(deps)*  [c325e79](https://github.com/emirror-de/webgates/commit/c325e79511186960e81fc7c18222971e9aa23100)

- Bump p384 from 0.13.1 to 0.14.0 Bumps [p384](https://github.com/RustCrypto/elliptic-curves) from 0.13.1 to 0.14.0. - [Commits](https://github.com/RustCrypto/elliptic-curves/compare/sm2/v0.13.1...p384/v0.14.0) --- updated-dependencies: - dependency-name: p384 dependency-version: 0.14.0 dependency-type: direct:production update-type: version-update:semver-minor ... Signed-off-by: dependabot[bot] <support@github.com> *(deps)*  [5710a76](https://github.com/emirror-de/webgates/commit/5710a7646945a21a5175367cde83730a9da53c45)

- Bump strum from 0.27.2 to 0.28.0 Bumps [strum](https://github.com/Peternator7/strum) from 0.27.2 to 0.28.0. - [Release notes](https://github.com/Peternator7/strum/releases) - [Changelog](https://github.com/Peternator7/strum/blob/master/CHANGELOG.md) - [Commits](https://github.com/Peternator7/strum/compare/v0.27.2...v0.28.0) --- updated-dependencies: - dependency-name: strum dependency-version: 0.28.0 dependency-type: direct:production update-type: version-update:semver-minor ... Signed-off-by: dependabot[bot] <support@github.com> *(deps)*  [c572197](https://github.com/emirror-de/webgates/commit/c572197f3ad450d43f2720c5576c21767ebfec80)

- Bump sha2 from 0.10.9 to 0.11.0 Bumps [sha2](https://github.com/RustCrypto/hashes) from 0.10.9 to 0.11.0. - [Commits](https://github.com/RustCrypto/hashes/compare/sha2-v0.10.9...sha2-v0.11.0) --- updated-dependencies: - dependency-name: sha2 dependency-version: 0.11.0 dependency-type: direct:production update-type: version-update:semver-minor ... Signed-off-by: dependabot[bot] <support@github.com> *(deps)*  [9df4e3c](https://github.com/emirror-de/webgates/commit/9df4e3c9c34bcce5906b5beb1951b870d789cfb8)



## [1.1.0] - 2026-08-10
### 📝 Other Changes
- Updated CHANGELOG.md [50911ff](https://github.com/emirror-de/webgates/commit/50911ffcccf78c6429409c49d3455e8c6f4fca1a)

- Updated audit.toml, added new vulnerability by surrealdb-types [b8446be](https://github.com/emirror-de/webgates/commit/b8446becfcf41dfc7df8598b3539499d5a52cd2d)

- Updated version numbers in markdown files [5033e16](https://github.com/emirror-de/webgates/commit/5033e16880bf6fffca04404d8d8472ab9a1b646a)

- Removed ignore flag for obsolete deny entry [f2d7355](https://github.com/emirror-de/webgates/commit/f2d73556ab3d04f7ccd44a7e8c4976da1a6df654)

- Upgraded dependencies, removed obsolete deny.toml entry [7e55160](https://github.com/emirror-de/webgates/commit/7e551609dfe5cc48704e2ae27b9e99d58cea2b51)

- Added cargo-semver-checks to flake.nix [8464bd2](https://github.com/emirror-de/webgates/commit/8464bd2eda3c623cc6b667191ff942adaa69ab23)

- Updated sea-orm to 2 [46f42fa](https://github.com/emirror-de/webgates/commit/46f42fa2fe13027405fd7086f45e7f6c6e372627)

- Upgrade versions to v1.1.0 [21df934](https://github.com/emirror-de/webgates/commit/21df934ea5dc5f1d89486d6cdf39304a5eb285a6)

- Added cargo workspaces to flake.nix [25500c8](https://github.com/emirror-de/webgates/commit/25500c855bbffa0c936a4bfa95c85045cb8b3ceb)

- Updated feature contract check script [082ddeb](https://github.com/emirror-de/webgates/commit/082ddeb1f046d3105845cfb1564d7bd113e47b81)

- Using session feature of surrealdb [fc96f71](https://github.com/emirror-de/webgates/commit/fc96f7114e92e95553471985cea141b25c35490c)

- Now using latest toolchain in flake.nix [0582def](https://github.com/emirror-de/webgates/commit/0582defc9a6c8e638c5d6bdd4f7b1254f6afee1b)

- Updated Cargo.lock [70637f4](https://github.com/emirror-de/webgates/commit/70637f43809f32af802f95583bafee5d40c10f5d)

- Moved ignored RUSTSEC items from CI definition to .cargo/audit.toml [b97d583](https://github.com/emirror-de/webgates/commit/b97d5833b635b257ab878624b7372ef49a239799)

- Added webgates-tonic to feature matrix [619d86c](https://github.com/emirror-de/webgates/commit/619d86c91888b70f9eb0d066a5c3a90ae6b97122)

- Added node_modules in any subdirectory to .gitignore [76592b9](https://github.com/emirror-de/webgates/commit/76592b9c6bbfc71d2001ed246c8fd7877bdc1a86)

- Updated Cargo.lock and flake.lock [cb7bc01](https://github.com/emirror-de/webgates/commit/cb7bc014b2d30494349aec606cd12faf17f13456)

- Temporary disabled cargo-watch due to compilation error [3b00b42](https://github.com/emirror-de/webgates/commit/3b00b42997c03b8836b247c9104797d7f532fa8a)

- Added proc-macro-error2 to deny.toml [72f476b](https://github.com/emirror-de/webgates/commit/72f476bfaa7ff369618467655c1cdd626c6ea018)

- Removed old advisories from deny.toml [eea00dc](https://github.com/emirror-de/webgates/commit/eea00dcc3662e706a48eea2073914cbb800f5ac3)

- Updated Rust version to 1.94 [844906c](https://github.com/emirror-de/webgates/commit/844906c7527e376acff989be25cb95f664790b4d)

- Updated workspace/flake version to v1.1.0-dev [c4fe6b9](https://github.com/emirror-de/webgates/commit/c4fe6b9d2de3672fffe1c0e494643f49f60d696e)

- Upgrade sea-orm to v2.0.0-rc.42 [0d86d98](https://github.com/emirror-de/webgates/commit/0d86d98623df879379ea04c94b0565e4cfa9066a)

- Added missing Display implementation for Group [f400006](https://github.com/emirror-de/webgates/commit/f4000062ed46c877e51d477eb8c2a97be8c5bb26)

- Custom roles serialization with sea-orm [0cbad8d](https://github.com/emirror-de/webgates/commit/0cbad8d2a7f781a2a5d92c45ebcf166eb1fa359f)



## [1.0.0] - 2026-05-13
### 🏗 Refactoring
- **💥 BREAKING CHANGE:** Login and logout modules are now public [edfac67](https://github.com/emirror-de/webgates/commit/edfac67e3e2b0d50ea3a3cbdcbd9992d3c16bf6f)

- Split up into several crates for better composability, Fixed a few bugs Co-authored-by: Lewin Probst <info@emirror.de> Co-committed-by: Lewin Probst <info@emirror.de> [89a3aeb](https://github.com/emirror-de/webgates/commit/89a3aeb9877e7f55b7c86625a45cf65e25fd4e36)



### 📝 Other Changes
- Updated Cargo.toml descriptions [75b11b9](https://github.com/emirror-de/webgates/commit/75b11b9167d7c64214a51dc2e142a2d7910d44c0)

- Updated README.md and webgates/README.md [19e330f](https://github.com/emirror-de/webgates/commit/19e330f54e26c295089a57469f3fae51c00e11e6)

- Updated CHANGELOG.md [93ecbf1](https://github.com/emirror-de/webgates/commit/93ecbf1367b037bde8aa7c5669a4cc4e9f76902c)

- Updated README.md crate list [a404a37](https://github.com/emirror-de/webgates/commit/a404a37916ab98d73c7d6f8acff73756cea45e6a)

- Updated distributed sessions guide and rustdoc sections [f12327b](https://github.com/emirror-de/webgates/commit/f12327bfa19e1998a10e308592bb422da344cefe)

- Removed unnecessary gitlab ci definition [11378ad](https://github.com/emirror-de/webgates/commit/11378ad3f5be27d7a549c7d20ac343f0337ef649)

- Updated version numbers within documentation, added CHANGELOG.md [672f267](https://github.com/emirror-de/webgates/commit/672f2676dc6cf2b68b45ca47d9d6d74117946baa)

- Updated documentation, version bump [8818a55](https://github.com/emirror-de/webgates/commit/8818a550296d8c29513c62a911b47e54732a28fd)

- Add ES384 key loader with codec/authority helpers and update examples [abd8307](https://github.com/emirror-de/webgates/commit/abd83074748bd6e9a80d8a112e65b51d739d39c8)

- Clarify missing and expired auth cookie session behavior [e72e512](https://github.com/emirror-de/webgates/commit/e72e51245f7b06e19e6e1e65f0d6af32b98a1a0b)

- Tighten rustdoc conventions across workspace crates [dc00934](https://github.com/emirror-de/webgates/commit/dc00934d2d6989ea45a84115e26908b98d7d395e)

- Updated documentation [9e34506](https://github.com/emirror-de/webgates/commit/9e345063c0be2e57115aa4672510ce1c48e1b82a)

- Updated version numbers in preparation for publishing [3bd29a3](https://github.com/emirror-de/webgates/commit/3bd29a3f963be425b461e4ab9866eda31a55829c)

- Updated documentation for release [381daee](https://github.com/emirror-de/webgates/commit/381daee16fb487a81ce52c69aa16e45cd6bc76f4)

- Added missing crypto provider installation to tests [9887e1b](https://github.com/emirror-de/webgates/commit/9887e1b1bd0461f2958f61b122881259f0240acd)

- Clippy deny expect_used [6947bb4](https://github.com/emirror-de/webgates/commit/6947bb44b409f20b1d69d3f1581e22aa66dda7c9)

- Make auth and oauth cookie defaults secure by default [f2c98b3](https://github.com/emirror-de/webgates/commit/f2c98b31feeb6228d1ea6fe17fbb086bcf053d4b)

- Updated documentation and registered claims [d52ca4a](https://github.com/emirror-de/webgates/commit/d52ca4a3cb4cabb82ac38bdf25b1d64740237c5a)

- Updated Cargo.lock [73fef18](https://github.com/emirror-de/webgates/commit/73fef18df1f58c1718d2a4b786e3121daf83d59a)

- Aligned webgates-tonic with best practices [b8459f3](https://github.com/emirror-de/webgates/commit/b8459f375b2f469fe1db3800a849e940992576c4)

- Added webgates-tonic crate [e09c9bf](https://github.com/emirror-de/webgates/commit/e09c9bfd6f529ba53f3b0efdf7fe67f1b8d79d5f)

- Timing repositories tests now finish faster [836ab75](https://github.com/emirror-de/webgates/commit/836ab75fe0b4124b7e2ec44234bbf3d25a49b726)

- Updated to match Rust quality preferences [3bc50f4](https://github.com/emirror-de/webgates/commit/3bc50f41c036c46ab190bf9243fef099dbe39d9b)

- Added missing kv-mem feature to surrealdb dependency [b77dfc5](https://github.com/emirror-de/webgates/commit/b77dfc5756a49b38cb204dfa7c043749dc2ae6d7)

- Removed surrealdb from workspace dependencies [9fe3222](https://github.com/emirror-de/webgates/commit/9fe322285e7b205e1cad4a8161541f288365cf7c)

- Updated documentation to the latest state [e56dc93](https://github.com/emirror-de/webgates/commit/e56dc9398a8f2e4188582389ea39b03c9d726052)

- Added missing cargo-tarpaulin to flake.nix [a1f0ea8](https://github.com/emirror-de/webgates/commit/a1f0ea896c08af0edc23bbdaeceabe59274da2d9)

- Upgrade rand dependency [d963a5d](https://github.com/emirror-de/webgates/commit/d963a5dab5a9c61e7ff6147478f829328f7fed5f)

- Cargo deny [53b7964](https://github.com/emirror-de/webgates/commit/53b79648b62bfd476bf2dfc44a0879a4df383ad3)

- Applied rustfmt [03d7a8c](https://github.com/emirror-de/webgates/commit/03d7a8cce8991faff1474f818a5e770d1a81ca40)

- Gate authn/secrets test imports and fix tracing doctest calls behind feature flags [ea9184b](https://github.com/emirror-de/webgates/commit/ea9184b4479bb3a7d148486105b98cb70c3ca767)

- Increased MSRV to 1.91 [842004c](https://github.com/emirror-de/webgates/commit/842004cd41fb885559f14fca2001a09ffa5f9247)

- Some compilation checks [d3d2f96](https://github.com/emirror-de/webgates/commit/d3d2f96612ce38f92f75541209f67c70930fc06e)

- Updated feature matrix and contract [b22ac58](https://github.com/emirror-de/webgates/commit/b22ac58a3f7f94cc32bef876fb5aebbda471b1e7)

- Sessions now using async traits [2a4c63b](https://github.com/emirror-de/webgates/commit/2a4c63bfe64202c8b95c879c6f19edbfd0ca1703)

- Added empty default feature to Cargo.toml in webgates-core [86744c4](https://github.com/emirror-de/webgates/commit/86744c4c0a106134ac899d4e1a5e66925c760c81)

- Trying to fix the CI [b794b4f](https://github.com/emirror-de/webgates/commit/b794b4f8422220f9a9e7610367a9d482b6ae6a66)

- CI was missing python pip [eee968a](https://github.com/emirror-de/webgates/commit/eee968a2e38376d02467924783f44706acd4b5ff)

- Updated README.md files, Updated CI, Added feature matrix and checks [def4d9f](https://github.com/emirror-de/webgates/commit/def4d9f1aa5e2921c14901ce611a8264691222b7)

- Gate optional modules, fix test expect/unwrap and guard features [eae563d](https://github.com/emirror-de/webgates/commit/eae563d85d594ad5700fbe0edea0baa911f50449)

- Added documentation to webgates-axum [74ba556](https://github.com/emirror-de/webgates/commit/74ba556a2a6a84e4d8ccf05cc3454c1b9458b810)

- Add runnable examples to all public structs [ef9d04e](https://github.com/emirror-de/webgates/commit/ef9d04e705c37aae5dd22fc22ba3c5c4ad0ed39a)

- Updated .gitignore [4bbb0ab](https://github.com/emirror-de/webgates/commit/4bbb0ab84196a0048bdf5a9dbbb04dc4b673122c)

- Moved memory session repository to webgates-repositories [9c8a06c](https://github.com/emirror-de/webgates/commit/9c8a06cf0a5f8420ff171b9d87ac9b3ea8a4cc20)

- Updated Account creation in memory repository docs [b5469b9](https://github.com/emirror-de/webgates/commit/b5469b9176d103667c2c9f50808be7b261100506)

- Updated wording [dece3aa](https://github.com/emirror-de/webgates/commit/dece3aab3c3ef61d90a20b7a14d4c69857511ff1)

- Updated CI workflow [ed47e25](https://github.com/emirror-de/webgates/commit/ed47e2502e6052d5923ea8481743467e65b59a58)

- Installed default crypto provider in test [2b2caa1](https://github.com/emirror-de/webgates/commit/2b2caa1dc34a25ccb7ead25dc694dcda1b999a34)

- Split up imports in doc test [fd2630a](https://github.com/emirror-de/webgates/commit/fd2630af87bdfc9d658a0196be4c1df4ffed9599)

- Added missing feature full to webgates [4b9a0c0](https://github.com/emirror-de/webgates/commit/4b9a0c038a7bd1090ea86ee0b71ea82c50bb87a5)

- Added webgates-secrets to workspace [0045fd4](https://github.com/emirror-de/webgates/commit/0045fd4ab92552186d38e919d3d7351d2d2e4da2)

- Sessions are only available when sessions feature is activated [7299162](https://github.com/emirror-de/webgates/commit/7299162a454ea4ec515ba02e6bc0449c6429cd2b)

- Dependency upgrades, Bearer token constant time comparison, Security fixes [9318a12](https://github.com/emirror-de/webgates/commit/9318a12d4c4fae616431f820aa7f1ff71e476f21)

- Update Account::new api, add with_roles and with_groups builders [b0d2f12](https://github.com/emirror-de/webgates/commit/b0d2f1270889ac4d81dbe52770d9c32fe7f252f8)

- Removed and ignored .DS_Store files [f5e0d86](https://github.com/emirror-de/webgates/commit/f5e0d866983c91c287ee526b2ea40526a1f2414d)

- Complete jwt auto-renewal integration and workspace validation [475aa6f](https://github.com/emirror-de/webgates/commit/475aa6f93a7abc7b807372f79d7d1aae1046a828)

- Moved profile from package to workspace [879d101](https://github.com/emirror-de/webgates/commit/879d1019ce59d35dfd7600fa60ce37f40c1adf2a)

- Added constructors to webgates_repository::surrealdb record types [18a7607](https://github.com/emirror-de/webgates/commit/18a7607dfc2db6e488a4d3ece8af0f99a27d5115)

- Updated .gitignore [f276a07](https://github.com/emirror-de/webgates/commit/f276a0732a92652939bc21d52108c9e28c680922)

- Use TryFrom for surreal account persistence conversions [2281136](https://github.com/emirror-de/webgates/commit/2281136f0e99ae5aadd67d7edacc57df8c57c7ba)

- Submodules of surrealdb are now public as well [8c4e6ff](https://github.com/emirror-de/webgates/commit/8c4e6ff0e0c110199f6edea31e3e2c41bbb67aff)

- Make SurrealDB persistence structs public [87fde65](https://github.com/emirror-de/webgates/commit/87fde651706b9ef2d90c59db60403b76b5cfcd19)

- Updated prelude modules [b920382](https://github.com/emirror-de/webgates/commit/b9203820f36044b68334cf8ffab662d16c417800)

- Updated all workspace = true dependencies [68c530a](https://github.com/emirror-de/webgates/commit/68c530a460a2424f1469811c58576be27746f3e5)

- Moved axum and axum-extra to webgates-axum instead of workspace dependencies [915db03](https://github.com/emirror-de/webgates/commit/915db03e5aa4e1dafa4b189285a904548843dbee)

- Moved tower and tower-http to webgates-axum instead of workspace dependencies [49ee508](https://github.com/emirror-de/webgates/commit/49ee508c9a1f721b38fe06ea29ef9b966ef31389)

- Added missing server feature gates [fd5c503](https://github.com/emirror-de/webgates/commit/fd5c50399ec7935e0e769e7a6f6950ee54389c3f)

- Update GitHUB CI [7d3eb80](https://github.com/emirror-de/webgates/commit/7d3eb80355cde7f79d6348362f0bd69037584ec0)

- Removed unnecessary block surroundings [2e5226c](https://github.com/emirror-de/webgates/commit/2e5226c1a5356e73b45c47dd6693c6c3979f2515)

- Removed warning about unused account_id if audit-logging feature is disabled [9aef22f](https://github.com/emirror-de/webgates/commit/9aef22f72e893a0e3b5e64a3304487ec82c254a9)

- Added missing exclamation mark [6a4f81b](https://github.com/emirror-de/webgates/commit/6a4f81b5659f99fbb9df230cbd4c59ac547f244e)

- Added LICENSE file [1650114](https://github.com/emirror-de/webgates/commit/16501144dc0df57bd0b82d39884db21d4029619d)

- Added allow clippy unwrap and expect for bearer tests [4b89c7f](https://github.com/emirror-de/webgates/commit/4b89c7f13c42e7ad1d65a6fc0b5589ec0b113fee)

- Updated documentation to the latest state [15176f1](https://github.com/emirror-de/webgates/commit/15176f174703b2e8b112b55feeb9125377f2dc6d)

- Tests [f1f05df](https://github.com/emirror-de/webgates/commit/f1f05dfa7ae44d0d0fa7e81b372690278982f0d0)

- Added bearer gate tests [f1cb71d](https://github.com/emirror-de/webgates/commit/f1cb71d7bdbf47d82eb181a985c770a315f233e4)

- Updated adapter [6abb9a1](https://github.com/emirror-de/webgates/commit/6abb9a12a9a83f29cf5250f841eb5284859a9d8f)

- Reordered module imports [b921993](https://github.com/emirror-de/webgates/commit/b92199319190cfe68ec2a21d5253dee2439b5713)

- Decoupling of errors [9797191](https://github.com/emirror-de/webgates/commit/9797191369b1fa400d62e5da6fe1b08037187a5c)

- Fixed doc-tests [e4feccc](https://github.com/emirror-de/webgates/commit/e4fecccf86112395cc5e39c4bc25ff3011c96683)

- Added examples how to implement gate adapter [1d31ab8](https://github.com/emirror-de/webgates/commit/1d31ab878720eb37489e5514b180489d56d1769d)

- Added example on how to create middleware for cookie gate [d21b530](https://github.com/emirror-de/webgates/commit/d21b5300c8d0603d8dd6b2da7bf8edf5bd464e00)

- Moved top-level docs of oauth2 gate to its module [5323420](https://github.com/emirror-de/webgates/commit/532342018984ab24270b2a2252b133d27f022303)

- Removed allow dead code configuration [9a2020d](https://github.com/emirror-de/webgates/commit/9a2020d444eb349578275c52fdbe5aae0c2d7218)

- Added audit-logging feature to docs.rs metadata [3503b24](https://github.com/emirror-de/webgates/commit/3503b24db9a89e7aa3aaa69d55667f621f96eab4)

- DummyRepository in tests has been denied because of unwrap used [2d9a43a](https://github.com/emirror-de/webgates/commit/2d9a43a0457f3aa8b61c41d3b63d99ced16ec3c1)

- Added missing webgates dependency feature [b5c27ab](https://github.com/emirror-de/webgates/commit/b5c27ab412d59bfe2a764f1e1f67281c78ec7f3c)

- Applied cargo fmt [86ab943](https://github.com/emirror-de/webgates/commit/86ab9439da47a93945f4a9782a207ef83e04ef96)

- No more mod.rs files [ed7f3e9](https://github.com/emirror-de/webgates/commit/ed7f3e95cd8445109b8dc400c0b3b4bd72267a9c)

- Moved .env file to .env.example in oauth2-github example [d31a3c6](https://github.com/emirror-de/webgates/commit/d31a3c6158f25b7b3226224c2f3220136b43674c)

- Added .env file in oauth2-github example to .gitignore [1b2f45e](https://github.com/emirror-de/webgates/commit/1b2f45e3a6259839121f1738215ef892c4624410)

- Applied clippy fix [bba2c48](https://github.com/emirror-de/webgates/commit/bba2c484ef2fb1920de1c31e8e2565df11df21c3)

- Applied cargo sort [929ac99](https://github.com/emirror-de/webgates/commit/929ac9909d5ba91eb649200de69c0033076f8417)

- Added workspace.package.version to Cargo.toml to satisfy crane [a865dff](https://github.com/emirror-de/webgates/commit/a865dfffd157b5ed427b42b0dc53e7ec3780fe7e)

- Tidied up dependencies [bd0bb22](https://github.com/emirror-de/webgates/commit/bd0bb22e06e1a60b20607d048a9254707a8c20f6)

- Moved errors module documentation into module [2be4ae0](https://github.com/emirror-de/webgates/commit/2be4ae0dba5b95e8349057ce60d26ad18557ed31)

- Renamed TableNames from AxumGate* to Webgates* [4d9d7ce](https://github.com/emirror-de/webgates/commit/4d9d7ce8f6a5745354226968e29cd7cd9592ce64)

- Removed useless server feature [83ac91b](https://github.com/emirror-de/webgates/commit/83ac91bf75269ede3795c94cd9b7b3ce4a9ada99)

- Removed unnecessary re-exports [ce86975](https://github.com/emirror-de/webgates/commit/ce86975d4fc07a8022a5c99fca4c4a7a3ac9fd53)

- Doc-tests webgates-axum [3865704](https://github.com/emirror-de/webgates/commit/3865704711b62233ef56c2c17af824f9baa4a891)

- Doc-tests [c52e720](https://github.com/emirror-de/webgates/commit/c52e7206b85d9002c7bedb5b95615b2e74ff09ec)

- Moved security features documentation to the appropriate place [aa000ee](https://github.com/emirror-de/webgates/commit/aa000eeb4f3aa6cbd8c73cf3dbe792812ab75577)

- Moved oauth2 crate to webgates [1c91843](https://github.com/emirror-de/webgates/commit/1c918432c772b484235d46e3cb8fb5cf5950616f)

- Transferred core domain logic of bearer gate to webgates, Removed unnecessary re-export of webgates within webgates-axum [21464ed](https://github.com/emirror-de/webgates/commit/21464ed02fc2567e35071bd31050e9a1fa7f9f87)

- Moved core logic of cookie gate into webgates crate [81b6cc6](https://github.com/emirror-de/webgates/commit/81b6cc64d884a4020f8acfba4d45a8f6d35ae7b9)

- Fully decoupling of repositories implementations to the main webgates crate [80d6fca](https://github.com/emirror-de/webgates/commit/80d6fcabb6a122df4e53680e5eeb3f5b7de2f822)

- Removed unnecessary line breaks [fe2ca9e](https://github.com/emirror-de/webgates/commit/fe2ca9edc332f70dadb192aa27f9624ba401a148)

- Removed server feature from webgates-axum [2a87825](https://github.com/emirror-de/webgates/commit/2a87825622a7e4c1513115e33ab1ea0b3d190add)

- Server feature is no longer default for webgates crate [ba59c41](https://github.com/emirror-de/webgates/commit/ba59c418eb28d74a0d3cbc6ff640f3e2fe43400e)

- Updated README.md [09fdb28](https://github.com/emirror-de/webgates/commit/09fdb28f1d6868b418bf87a0c4d8d9b9fc0323e2)

- Updated README.md [a320b02](https://github.com/emirror-de/webgates/commit/a320b02a2ffca593af72b1d0ec559fd87d6a9115)

- Updated documentation [4d1fa46](https://github.com/emirror-de/webgates/commit/4d1fa4614a5c400192128f45e6af9d9adb7854c4)

- Timing attack protection [03c5682](https://github.com/emirror-de/webgates/commit/03c5682e27776468e8ec72d2731d04628a88bd35)

- Doc tests [546eeb3](https://github.com/emirror-de/webgates/commit/546eeb3453fb58567a75c545dbe1fadd3eb823c2)

- Further updates on refactoring [adbbdef](https://github.com/emirror-de/webgates/commit/adbbdefa0ff229f4268d3e1f5735d783f60a2357)

- Updated README in oauth2 example [566f881](https://github.com/emirror-de/webgates/commit/566f881b5b2acd7ec114332fdb011bf59b1559fe)

- Removed hardcoded domain within oauth2 github [580ddce](https://github.com/emirror-de/webgates/commit/580ddce8a85f21f78d0a645a5a0cbe427f53f782)

- Missing tracing crate [b27e7fc](https://github.com/emirror-de/webgates/commit/b27e7fcbc40f36a3ba0436052d5719482d23e1fb)

- Updated implementations to the new structure [737b7b8](https://github.com/emirror-de/webgates/commit/737b7b8f9237a30e5b47199876d83857fa8a3450)

- Paths in examples of webgates-repositories [afd4159](https://github.com/emirror-de/webgates/commit/afd4159a904c51514bcd24aee63b6ce0f79dcd30)

- Added webgates-repositories crate [7a77330](https://github.com/emirror-de/webgates/commit/7a77330480a1a3249afafa087e5195564c7e3c03)

- Updated change of nixfmt package [80b3f56](https://github.com/emirror-de/webgates/commit/80b3f56bf98869523c086299c9c1724081e9d541)

- Applied some fixes [4c84633](https://github.com/emirror-de/webgates/commit/4c84633e715754993cfaf528d5fc64054340fcd9)

- Split up into webgates and webgates-axum [7209273](https://github.com/emirror-de/webgates/commit/7209273367b3cc4e93b2ffb4af0419e770ece105)

- Added .cargo/audit.toml configuration [0b4408e](https://github.com/emirror-de/webgates/commit/0b4408e61bc4427158aac9fc130f04638dcfebac)

- Applied rustfmt to examples [6e2a6bc](https://github.com/emirror-de/webgates/commit/6e2a6bc2476c28a26b149f047da9aae73ef85797)

- Applied rustfmt [44e31f5](https://github.com/emirror-de/webgates/commit/44e31f548a7b14ebc3e69290b233bc94efaeda5a)

- Re-added github workflows [87de2d5](https://github.com/emirror-de/webgates/commit/87de2d5578401dcad612439e6dbcf8becb8ec150)

- Renamed to webgates [6ad2c18](https://github.com/emirror-de/webgates/commit/6ad2c183ecb6e348b9cc5c5cb25764cb450379e4)

- Added initial axum-gate implementations [8e5c1ac](https://github.com/emirror-de/webgates/commit/8e5c1ac922ba844ed5bf7fd4a7e336f87ffa287e)

- Updated cliff configuration file [4d0e17e](https://github.com/emirror-de/webgates/commit/4d0e17eb85489d4a2a23c27b1b748c89089cb227)

- Started adding core modules [cd6ea1e](https://github.com/emirror-de/webgates/commit/cd6ea1e5168968e56559de96caeede1cf3bba5b1)

- Added initial Cargo and flake files [894b416](https://github.com/emirror-de/webgates/commit/894b416571e48eb1e87706b7a4935684e2c43f6d)

- Added .envrc [3cef4cd](https://github.com/emirror-de/webgates/commit/3cef4cd458710c68aeb57bed6151251bd05b90d5)

- Added deny, cliff and taplo configuration files [f84b64a](https://github.com/emirror-de/webgates/commit/f84b64a73a914f428f9c0f55472ee4694445c3ab)

- Updated .gitignore [47f9493](https://github.com/emirror-de/webgates/commit/47f94937343deb65558627988480c939518fad68)



---

<!-- generated by git-cliff -->
