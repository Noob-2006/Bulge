# home-manager: services.ark.enable = true;
self: { config, lib, pkgs, ... }:
let cfg = config.services.ark; in {
  options.services.ark = {
    enable = lib.mkEnableOption "ark agent daemon";
    package = lib.mkOption { type = lib.types.package; default = self.packages.${pkgs.stdenv.hostPlatform.system}.default; };
    workspace = lib.mkOption { type = lib.types.str; default = config.home.homeDirectory; };
    path = lib.mkOption { type = lib.types.listOf lib.types.package; default = with pkgs; [ bash coreutils git nodejs ]; description = "Tools the agent's commands can use."; };
  };
  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];
    systemd.user.services.arkd = {
      Unit = { Description = "ark agent daemon"; After = [ "network-online.target" ]; };
      Service = {
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = "${cfg.package}/bin/ark daemon run -w ${cfg.workspace}";
        Environment = [ "PATH=${lib.makeBinPath cfg.path}" ];
        Restart = "on-failure";
        RestartSec = "2s";
        KillMode = "mixed";
        TimeoutStopSec = "20s";
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        UMask = "0077";
      };
      Install.WantedBy = [ "default.target" ];
    };
  };
}
