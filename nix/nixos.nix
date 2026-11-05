# NixOS: services.seagent.enable = true;  (system instance, user `seagent`; FHS layout of seagent_core::layout::system:
# config /etc/seagent, state /var/lib/seagent, cache /var/cache/seagent, logs /var/log/seagent, runtime /run/seagent)
self: { config, lib, pkgs, ... }:
let cfg = config.services.seagent; in {
  options.services.seagent = {
    enable = lib.mkEnableOption "seagent agent daemon";
    package = lib.mkOption { type = lib.types.package; default = self.packages.${pkgs.stdenv.hostPlatform.system}.default; };
    path = lib.mkOption { type = lib.types.listOf lib.types.package; default = with pkgs; [ bash coreutils git nodejs ]; };
  };
  config = lib.mkIf cfg.enable {
    users.users.seagent = { isSystemUser = true; group = "seagent"; home = "/var/lib/seagent"; };
    users.groups.seagent = { };
    # /etc/seagent: config + secrets of the instance next to root-owned policy (sticky: seagent cannot replace root files)
    systemd.tmpfiles.rules = [ "d /etc/seagent 1770 root seagent -" ];
    systemd.services.seagentd = {
      description = "seagent agent daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      path = cfg.path;
      environment = { SEAGENT_MODE = "system"; };
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        User = "seagent";
        Group = "seagent";
        StateDirectory = [ "seagent" "seagent/workspace" ];
        StateDirectoryMode = "0750";
        CacheDirectory = "seagent";
        LogsDirectory = "seagent";
        RuntimeDirectory = "seagent";
        RuntimeDirectoryMode = "0750";
        ReadWritePaths = [ "-/etc/seagent" ];
        WorkingDirectory = "/var/lib/seagent";
        ExecStart = "${cfg.package}/bin/seagent daemon run -w /var/lib/seagent/workspace";
        Restart = "on-failure";
        RestartSec = "5s";
        KillMode = "mixed";
        TimeoutStopSec = "30s";
        Delegate = true; # ent-024: per-command cgroups ([exec.cgroups])
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
