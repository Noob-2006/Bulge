{
  description = "ark — self-hosted Linux-first AI agent";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, crane, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;
        # The UI files under ui/ are embedded with include_str!, so keep them in the source.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type: (craneLib.filterCargoSources path type) || (builtins.match ".*/ui/.*" path != null) || (builtins.match ".*/crates/ark-channel/data/.*" path != null);
        };
        common = { inherit src; strictDeps = true; pname = "ark"; };
        cargoArtifacts = craneLib.buildDepsOnly common;
        ark = craneLib.buildPackage (common // { inherit cargoArtifacts; cargoExtraArgs = "--bin ark"; doCheck = false; });
      in {
        packages.default = ark;
        checks = {
          inherit ark;
          clippy = craneLib.cargoClippy (common // { inherit cargoArtifacts; cargoClippyExtraArgs = "--all-targets -- -D warnings"; });
          tests = craneLib.cargoTest (common // { inherit cargoArtifacts; });
        };
        devShells.default = craneLib.devShell { checks = self.checks.${system}; packages = [ pkgs.python3 ]; };
      }) // {
      nixosModules.default = import ./nix/nixos.nix self;
      homeManagerModules.default = import ./nix/hm.nix self;
    };
}
