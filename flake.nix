{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
        extensions = ["rust-src" "rust-analyzer"];
      };

      cargoToml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");

      mcp-server-gdb-pkg = pkgs.rustPlatform.buildRustPackage {
        pname = cargoToml.package.name;
        version = cargoToml.package.version;
        src = self;

        cargoLock = {
          lockFile = "${self}/Cargo.lock";
        };

        nativeBuildInputs = with pkgs; [
          pkg-config
          perl
        ];
        buildInputs = with pkgs; [
          gdb
          openssl
          openssl.dev
        ];

        # Use system OpenSSL provided by buildInputs instead of vendored build.
        OPENSSL_NO_VENDOR = "1";
      };
    in {
      packages.default = mcp-server-gdb-pkg;

      apps.default = flake-utils.lib.mkApp {
        drv = mcp-server-gdb-pkg;
      };

      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          rustToolchain

          # Build utilities needed by C build scripts (e.g. openssl-sys, aws-lc-sys).
          pkg-config
          perl

          # C toolchain: linker (cc) + headers required by build scripts.
          gcc
          binutils

          # OpenSSL dev headers for openssl-sys (system, not vendored).
          openssl
          openssl.dev

          # GDB runtime: used by integration tests and direct debugging.
          gdb

          # QEMU: user-mode + system-mode for all target architectures.
          # Provides qemu-<arch> and qemu-system-<arch> binaries used by the
          # qemu-user / qemu-system backend and the test suite.
          qemu
        ];

        # Tell openssl-sys to use the system OpenSSL (not the vendored build)
        # so that the Perl Configure script and C compiler are not required at
        # `cargo check / build` time inside the dev shell.
        OPENSSL_NO_VENDOR = "1";

        shellHook = ''
          echo "Development environment activated"
          echo ""
        '';
      };
    });
}
