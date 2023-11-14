{
  description = "IDA Scripts";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = {
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [rust-overlay.overlays.default];
          config.allowUnfree = true;
        };
      in rec {
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            alejandra
            pyright
            (python3.withPackages (ps: with ps; [debugpy]))
          ];
        };
      }
    );
}
