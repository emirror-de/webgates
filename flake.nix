{
  description = "Protection for your Rust web application";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-analyzer-src.follows = "";
    };

    flake-utils.url = "github:numtide/flake-utils";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      fenix,
      flake-utils,
      advisory-db,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) lib;

        # Use latest Rust toolchain
        rustToolchain = fenix.packages.${system}.latest.toolchain;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            (lib.hasSuffix "\.rs" path)
            || (lib.hasSuffix "\.toml" path)
            || (lib.hasSuffix "\.lock" path)
            || (lib.hasSuffix "\.md" path)
            || (type == "directory");
        };

        # Common arguments can be set here to avoid repeating them later
        # For workspace projects, explicitly set metadata to avoid warnings
        commonArgs = {
          inherit src;
          pname = "webgates";
          version = "1.1.0-dev";
          strictDeps = true;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs =
            with pkgs;
            [
              openssl
            ]
            ++ lib.optionals pkgs.stdenv.isDarwin [
              libiconv
            ];

          # Set environment variables for OpenSSL
          OPENSSL_NO_VENDOR = 1;
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        };

        # Toolchain with LLVM tools for coverage
        craneLibLLvmTools = craneLib.overrideToolchain (
          fenix.packages.${system}.latest.withComponents [
            "cargo"
            "llvm-tools"
            "rustc"
          ]
        );

        # Build cargo dependencies
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the library
        webgates = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            doCheck = false; # Tests run separately in checks
          }
        );
      in
      {
        checks = {
          # Build the package as part of `nix flake check`
          inherit webgates;

          # Run clippy with all warnings denied
          webgates-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );

          # Generate documentation
          webgates-doc = craneLib.cargoDoc (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );

          # Check code formatting
          webgates-fmt = craneLib.cargoFmt {
            inherit src;
            pname = "webgates";
          };

          # Check TOML formatting
          webgates-toml-fmt = craneLib.taploFmt {
            src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
            pname = "webgates";
            taploExtraArgs = "--config ./taplo.toml";
          };

          # Security audit
          webgates-audit = craneLib.cargoAudit {
            inherit src advisory-db;
            pname = "webgates";
          };

          # License and dependency checks
          webgates-deny = craneLib.cargoDeny {
            inherit src;
            pname = "webgates";
          };

          # Run tests with cargo-nextest
          webgates-nextest = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
            }
          );
        };

        packages = {
          default = webgates;
        }
        // lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
          # LLVM coverage only on non-Darwin systems
          webgates-llvm-coverage = craneLibLLvmTools.cargoLlvmCov (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );
        };

        # No apps needed for a library crate

        devShells.default = craneLib.devShell {
          name = "webgates-dev";

          # Inherit inputs from checks
          checks = self.checks.${system};

          # Development packages for library development
          packages =
            with pkgs;
            [
              # Rust development tools
              rust-analyzer
              rustfmt
              clippy

              # Build tools
              pkg-config

              # Python tooling for repository scripts
              python3
              python3Packages.toml

              # Nix tools
              nil
              nixfmt

              # TOML formatting
              taplo

              # Library development tools
              cargo-audit
              cargo-deny
              cargo-nextest
              #cargo-watch # temporary disabled due to compile error on macos
              cargo-sort
              cargo-expand # For macro debugging
              cargo-machete # For unused dependency detection

              # Database tools for examples
              sqlite
            ]
            ++ lib.optionals (!pkgs.stdenv.isDarwin) [
              cargo-llvm-cov
              cargo-tarpaulin
            ];

          # Environment variables
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          OPENSSL_NO_VENDOR = 1;
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        };

        # Formatter for the flake itself
        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
