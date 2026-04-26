{
  description = "Prophet Python ML runtime scaffold for Lattice Forge";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          prophet-python-ml = pkgs.buildEnv {
            name = "prophet-python-ml-runtime";
            paths = with pkgs; [
              python311
              python311Packages.pip
              python311Packages.ipykernel
              python311Packages.numpy
              python311Packages.pandas
              python311Packages.pyarrow
              python311Packages.scikit-learn
              python311Packages.jupyterlab
              git
              jq
            ];
          };
          default = self.packages.${system}.prophet-python-ml;
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = [ self.packages.${system}.prophet-python-ml ];
          };
        });
    };
}
