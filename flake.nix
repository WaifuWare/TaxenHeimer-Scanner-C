{
  description = "TaxhenHeimer Dev Shell";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2411.*.tar.gz";
  };

  outputs = { nixpkgs, ... }:
    let
      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });

    in
    {
      devShells = forAllSystems ({ pkgs }:
        let libs = with pkgs; [
            clang
            curl
            readline70
          ];
        in
        {
          default = (
              pkgs.mkShell.override {
                stdenv = pkgs.llvmPackages_12.stdenv;
              }
          ) rec {
            env.CC = "clang";
            env.NIX = 1;
            LD_LIBRARY_PATH = "/run/opengl-driver/lib";
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            packages = with pkgs; [
              clang-tools
              clang
              libllvm
              gnumake
              pkg-config
              gdb
              valgrind
            ];
            nativeBuildInputs = packages;
            buildInputs = libs;
			shellHook = ''
MY_PWD=$(pwd)
cat <<EOL > "./.clangd"
CompileFlags:
	Add:
		- "-I${pkgs.glibc.dev}/include"
		- "-I${pkgs.readline70.dev}/include"
EOL
			'';
          };
        }
      );
    };
}
