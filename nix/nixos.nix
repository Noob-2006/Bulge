# NixOS: services.ark.enable = true;  (system instance, user `ark`, state in /var/lib/ark)
self: { config, lib, pkgs, ... }:
let cfg = config.services.ark; in {
  options.services.ark = {
    enable = lib.mkEnableOption "ark agent daemon";
    package = lib.mkOption { type = lib.types.package; default = self.packages.${pkgs.stdenv.hostPlatform.system}.default; };
    path = lib.mkOption { type = lib.types.listOf lib.types.package; default = with pkgs; [ bash coreutils git nodejs ]; };
  };
  config = lib.mkIf cfg.enable {
    users.users.ark = { isSystemUser = true; group = "ark"; home = "/var/lib/ark"; };
    users.groups.ark = { };
    systemd.services.arkd = {
      description = "ark agent daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      path = cfg.path;
      environment = { ARK_HOME = "/var/lib/ark"; };
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        User = "ark";
        Group = "ark";
        StateDirectory = [ "ark" "ark/workspace" ];
        StateDirectoryMode = "0750";
        WorkingDirectory = "/var/lib/ark";
        ExecStart = "${cfg.package}/bin/ark daemon run -w /var/lib/ark/workspace";
        Restart = "on-failure";
        RestartSec = "5s";
        KillMode = "mixed";
        TimeoutStopSec = "30s";
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        RestrictRealtime = true;
        PrivateTmp = true;
        ProtectSystem = "full";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        UMask = "0077";
      };
    };
  };
}
