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

        # Enable QEMU user-mode and system-mode debugging support.
        buildFeatures = [ "qemu-user" "qemu-system" ];

        nativeBuildInputs = with pkgs; [
          pkg-config
          perl
          makeWrapper
        ];
        buildInputs = with pkgs; [
          gdb
          openssl
          openssl.dev
        ];

        # Integration tests require a live GDB process which is not available
        # inside the Nix build sandbox.
        doCheck = false;

        # Apply local patches to vendored submodules before the build.
        patches = [
          ./patches/0001-gef-fix-read-permission-check-for-cached-temp-files.patch
        ];
        patchFlags = [ "-p1" "--directory=vendor/gef" ];

        # Install gef.py and wrap the binary so that gdb and all qemu-*
        # binaries are always on PATH regardless of the calling environment.
        postInstall = ''
          mkdir -p $out/share/gef
          cp vendor/gef/gef.py $out/share/gef/gef.py

          wrapProgram $out/bin/mcp-server-gdb \
            --prefix PATH : ${pkgs.lib.makeBinPath (with pkgs; [ gdb qemu ])}
        '';

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

          # Ensure vendor/gef submodule is initialised for tests and local runs.
          if [ ! -f vendor/gef/gef.py ]; then
            echo "Initialising vendor/gef submodule..."
            git submodule update --init vendor/gef
          fi

          # Apply local patches to vendor/gef if not already applied.
          for patch in patches/*.patch; do
            if patch -d vendor/gef -p1 --dry-run --reverse --silent < "$patch" 2>/dev/null; then
              echo "Already applied: $patch"
            else
              echo "Applying $patch..."
              patch -d vendor/gef -p1 < "$patch"
            fi
          done
        '';
      };
    })
    // {
      # Nixpkgs overlay: exposes mcp-server-gdb as pkgs.mcp-server-gdb
      overlays.default = final: _prev: {
        mcp-server-gdb = self.packages.${final.system}.default;
      };

      # Home Manager module: declarative systemd user service
      homeManagerModules.default = import ./nix/home-manager-module.nix { inherit self; };
    };
}
