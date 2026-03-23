{
  system ? builtins.currentSystem,
  pkgs ? import <nixpkgs> {
    inherit system;
  }
}:
pkgs.stdenv.mkDerivation {
  name = "docker-boot";
  src = pkgs.lib.cleanSource ./.;

  buildInputs = with pkgs; [
    coreutils
    docker
    gnutar
    util-linux
  ];

  installPhase = ''
    install -Dm755 docker-boot $out/bin/docker-boot
  '';

  meta = {
    description = "Like `execve`, but for userspace";
    mainProgram = "docker-boot";
    license = pkgs.lib.licenses.wtfpl;
  };
}
