
{
  description = "Neon Secure Network System";
  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
  in {
    packages = forAllSystems (pkgs: pkgs.stdenv.mkDerivation {
      pname = "neonsec";
      version = "1.0.0";
      src = ./.;
      nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config ];
      buildInputs = [];
      buildPhase = ''
        cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
        cmake --build build -j
      '';
      installPhase = ''
        mkdir -p $out/bin
        cp build/neonsec $out/bin/
      '';
    });
    defaultPackage = self.packages.x86_64-linux;
  };
}
