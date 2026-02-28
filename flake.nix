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
        extensions = ["rust-src"];
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
        ];
      };
    in {
      packages.default = mcp-server-gdb-pkg;

      apps.default = flake-utils.lib.mkApp {
        drv = mcp-server-gdb-pkg;
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [mcp-server-gdb-pkg];
        buildInputs = with pkgs; [
          rustToolchain
          cargo
          clippy

          # QEMU: user-mode + system-mode for all target architectures.
          # Provides qemu-<arch> and qemu-system-<arch> binaries used by the
          # qemu-user / qemu-system backend and the test suite.
          qemu
        ];

        shellHook = ''
          echo "Development environment activated"
          echo ""
        '';
      };
    });
}
