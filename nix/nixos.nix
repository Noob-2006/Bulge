# NixOS: services.ark.enable = true;  (system instance, user `ark`; FHS layout of ark_core::layout::system:
# config /etc/ark, state /var/lib/ark, cache /var/cache/ark, logs /var/log/ark, runtime /run/ark)
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
    # /etc/ark: config + secrets of the instance next to root-owned policy (sticky: ark cannot replace root files)
    systemd.tmpfiles.rules = [ "d /etc/ark 1770 root ark -" ];
    systemd.services.arkd = {
      description = "ark agent daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      path = cfg.path;
      environment = { ARK_MODE = "system"; };
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        User = "ark";
        Group = "ark";
        StateDirectory = [ "ark" "ark/workspace" ];
        StateDirectoryMode = "0750";
        CacheDirectory = "ark";
        LogsDirectory = "ark";
        RuntimeDirectory = "ark";
        RuntimeDirectoryMode = "0750";
        ReadWritePaths = [ "-/etc/ark" ];
        WorkingDirectory = "/var/lib/ark";
        ExecStart = "${cfg.package}/bin/ark daemon run -w /var/lib/ark/workspace";
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
