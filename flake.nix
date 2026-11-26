{
  description = "odin-fuzz: automated integration and invariant testing for Odin applications on macOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/619c39f6eac5d1ed6b8f073a9414baf7034b2356";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      flakeLock = builtins.fromJSON (builtins.readFile ./flake.lock);

      cleanSrc = nixpkgs.lib.fileset.toSource {
        root = ./.;
        fileset = nixpkgs.lib.fileset.unions [
          ./odin-fuzz
          ./tools/odin_fuzz.py
          ./src
          ./LICENSE
          ./GUIDE.md
          ./README.md
        ];
      };

      mkOdinFuzz =
        {
          pkgs,
          odin,
          llvmPackages,
          python3 ? pkgs.python315,
          src ? cleanSrc,
          version ? "0.5.0",
          patches ? [ ],
        }:
        pkgs.callPackage ./nix/package.nix {
          inherit
            odin
            llvmPackages
            python3
            src
            version
            patches
            ;
        };

      mkContext =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          toolchain = import ./nix/llvm23/llvm23-toolchain.nix { inherit pkgs; };
          odinFuzzPkg = mkOdinFuzz {
            inherit pkgs;
            inherit (toolchain) odin llvmPackages;
            python3 = toolchain.python;
          };
          updates = {
            schema = 1;
            dependencies = [
              {
                name = "nixpkgs";
                current = flakeLock.nodes.nixpkgs.locked.rev;
                kind = "github-revision";
                repository = "${flakeLock.nodes.nixpkgs.locked.owner}/${flakeLock.nodes.nixpkgs.locked.repo}";
                ref = "nixpkgs-unstable";
              }
              {
                name = "odin";
                current = toolchain.odin.version;
                kind = "github-release";
                repository = "odin-lang/Odin";
              }
            ];
          };
        in
        {
          inherit
            pkgs
            toolchain
            odinFuzzPkg
            updates
            ;
        };
    in
    {
      lib = {
        inherit mkOdinFuzz;
        dependencyCheck = forAllSystems (
          system:
          let
            ctx = mkContext system;
            interpreter = ctx.pkgs.python315;
          in
          {
            inherit interpreter;
            python = "${interpreter}/bin/python3";
            preferredPython = "${ctx.toolchain.python}/bin/python3";
            metadata = ctx.updates;
          }
        );
      };

      packages = forAllSystems (
        system:
        let
          ctx = mkContext system;
          envManifest = ctx.pkgs.writeTextDir "share/project-environment.json" (
            builtins.toJSON {
              schema = 1;
              variables = {
                ODIN = "${ctx.toolchain.odin}/bin/odin";
                ODIN_ROOT = "${ctx.toolchain.odin}/share";
              };
              unset = [ ];
            }
          );
          updateManifest = ctx.pkgs.writeTextDir "share/dependency-updates.json" (
            builtins.toJSON ctx.updates
          );
          devPackages = [
            ctx.toolchain.odin
            ctx.toolchain.llvmPackages.clang
            ctx.toolchain.llvmPackages.llvm
            ctx.toolchain.python
            envManifest
            updateManifest
          ];
        in
        {
          default = ctx.odinFuzzPkg;
          odin-fuzz = ctx.odinFuzzPkg;
          dev-environment = ctx.pkgs.buildEnv {
            name = "odin-fuzz-dev-environment";
            paths = devPackages;
            pathsToLink = [
              "/bin"
              "/share"
            ];
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.odin-fuzz}/bin/odin-fuzz";
        };
        odin-fuzz = {
          type = "app";
          program = "${self.packages.${system}.odin-fuzz}/bin/odin-fuzz";
        };
      });

      devShells = forAllSystems (
        system:
        let
          ctx = mkContext system;
        in
        {
          default = ctx.pkgs.mkShellNoCC {
            packages = [
              ctx.toolchain.odin
              ctx.toolchain.llvmPackages.clang
              ctx.toolchain.llvmPackages.llvm
              ctx.toolchain.python
            ];
            ODIN = "${ctx.toolchain.odin}/bin/odin";
            ODIN_ROOT = "${ctx.toolchain.odin}/share";
          };
        }
      );
    };
}
