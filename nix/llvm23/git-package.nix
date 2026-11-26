{ pkgs, python }:
let
  dependencies = import ./native-dependencies.nix { inherit pkgs; };
in dependencies.git.override {
  python3 = python;
  inherit (dependencies) perlPackages curl expat;
  inherit (dependencies.rust.packages.stable) cargo rustc;
}
