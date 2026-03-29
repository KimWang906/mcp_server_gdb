# Home Manager module for mcp-server-gdb.
# Imported by flake.nix as homeManagerModules.default.
# `self` is the mcp-server-gdb flake, injected via the `specialArgs` closure.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.mcp-server-gdb;
in
{
  options.services.mcp-server-gdb = {
    enable = lib.mkEnableOption "MCP GDB debug server (SSE transport)";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.default;
      defaultText = lib.literalExpression "mcp-server-gdb";
      description = "The mcp-server-gdb package to use.";
    };

    transport = lib.mkOption {
      type = lib.types.enum [
        "stdio"
        "sse"
      ];
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
      type = lib.types.enum [
        "trace"
        "debug"
        "info"
        "warn"
        "error"
      ];
      default = "info";
      description = "Log verbosity level.";
    };

    gdbTimeout = lib.mkOption {
      type = lib.types.ints.positive;
      default = 10;
      description = "GDB command execution timeout in seconds.";
    };

    # Defaults to the canonical configs/gef.rc shipped with this flake.
    gefRcFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = "${self}/configs/gef.rc";
      defaultText = lib.literalExpression ''"''${mcp-server-gdb}/configs/gef.rc"'';
      description = ''
        Path to a GEF rc file passed to --gef-rc at startup.
        Defaults to the configs/gef.rc bundled with the mcp-server-gdb flake.
        Set to null to omit the flag entirely.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.user.services.mcp-server-gdb = {
      Unit = {
        Description = "MCP GDB Debug Server";
        After = [ "network.target" ];
      };

      Service = {
        Type = "simple";
        # transport is a positional argument, not --transport
        ExecStart = lib.concatStringsSep " " (
          [
            "${cfg.package}/bin/mcp-server-gdb"
            cfg.transport
            "--log-level"
            cfg.logLevel
          ]
          ++ lib.optionals (cfg.gefRcFile != null) [
            "--gef-rc"
            (toString cfg.gefRcFile)
          ]
        );
        Environment = [
          "SERVER_IP=${cfg.ip}"
          "SERVER_PORT=${toString cfg.port}"
          "GDB_COMMAND_TIMEOUT=${toString cfg.gdbTimeout}"
        ];
        Restart = "on-failure";
        RestartSec = "5s";
      };

      Install.WantedBy = [ "default.target" ];
    };
  };
}
