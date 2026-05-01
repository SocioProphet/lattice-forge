{
  description = "Prophet Ray ML demo runtime for Lattice Studio ModelOps";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system);
    in {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.buildEnv {
            name = "prophet-ray-ml-runtime";
            paths = with pkgs; [
              python311
              python311Packages.ipykernel
              python311Packages.numpy
              python311Packages.pandas
              python311Packages.pyarrow
              python311Packages.scikit-learn
              python311Packages.ray
              duckdb
              jq
            ];
          };
        });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = [ self.packages.${system}.default ];
          };
        });
    };
}
