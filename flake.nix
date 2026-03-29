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

        # Integration tests require a live GDB process which is not available
        # inside the Nix build sandbox.
        doCheck = false;

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
    })
    // {
      # Nixpkgs overlay: exposes mcp-server-gdb as pkgs.mcp-server-gdb
      overlays.default = final: _prev: {
        mcp-server-gdb = self.packages.${final.system}.default;
      };

      # Home Manager module: declarative systemd user service
      homeManagerModules.default = {
        config,
        lib,
        pkgs,
        ...
      }: let
        cfg = config.services.mcp-server-gdb;
      in {
        options.services.mcp-server-gdb = {
          enable = lib.mkEnableOption "MCP GDB debug server (SSE transport)";

          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.system}.default;
            defaultText = lib.literalExpression "mcp-server-gdb";
            description = "The mcp-server-gdb package to use.";
          };

          transport = lib.mkOption {
            type = lib.types.enum ["stdio" "sse"];
            default = "sse";
            description = ''
              Transport type.  Use "sse" for a persistent HTTP/SSE server
              and "stdio" for subprocess-spawned MCP clients.
            '';
          };

          ip = lib.mkOption {
            type = lib.types.str;
            default = "127.0.0.1";
            description = "Bind address for the SSE HTTP server.";
          };

          port = lib.mkOption {
            type = lib.types.port;
            default = 7774;
            description = "TCP port for the SSE HTTP server.";
          };

          logLevel = lib.mkOption {
            type = lib.types.enum ["trace" "debug" "info" "warn" "error"];
            default = "info";
            description = "Log verbosity level.";
          };

          gdbTimeout = lib.mkOption {
            type = lib.types.ints.positive;
            default = 10;
            description = "GDB command execution timeout in seconds.";
          };

          gefRcFile = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            default = null;
            example = lib.literalExpression ''"''${config.home.homeDirectory}/.gef.rc"'';
            description = "Optional path to a GEF rc file loaded at session start.";
          };
        };

        config = lib.mkIf cfg.enable {
          systemd.user.services.mcp-server-gdb = {
            Unit = {
              Description = "MCP GDB Debug Server";
              After = ["network.target"];
            };

            Service = {
              Type = "simple";
              ExecStart = lib.concatStringsSep " " (
                [
                  "${cfg.package}/bin/mcp-server-gdb"
                  "--transport"
                  cfg.transport
                  "--log-level"
                  cfg.logLevel
                ]
                ++ lib.optionals (cfg.gefRcFile != null) ["--gef-rc" (toString cfg.gefRcFile)]
              );
              Environment = [
                "SERVER_IP=${cfg.ip}"
                "SERVER_PORT=${toString cfg.port}"
                "GDB_COMMAND_TIMEOUT=${toString cfg.gdbTimeout}"
              ];
              Restart = "on-failure";
              RestartSec = "5s";
            };

            Install.WantedBy = ["default.target"];
          };
        };
      };
    };
}
