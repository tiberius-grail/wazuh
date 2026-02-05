{
  description = "Wazuh Agent for NixOS";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    {
      overlays = {
        default = final: prev: {
          wazuh-agent = final.callPackage ./pkgs/wazuh-agent.nix {
            # Use GCC 14 to avoid incompatible-pointer-types errors in GCC 15
            stdenv = final.gcc14Stdenv;
          };
        };
        # Legacy alias
        wazuh = self.overlays.default;
      };
      nixosModules = {
        wazuh-agent = import ./modules/wazuh-agent;
        default = self.nixosModules.wazuh-agent;
      };
    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        formatter = pkgs.alejandra;
        packages = {
          wazuh-agent = pkgs.callPackage ./pkgs/wazuh-agent.nix {
            # Use GCC 14 to avoid incompatible-pointer-types errors in GCC 15
            stdenv = pkgs.gcc14Stdenv;
          };
          default = self.packages.${system}.wazuh-agent;
        };
      }
    );
}
