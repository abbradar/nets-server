{ mypkgs ? import /home/shlomo/cgate { } }:

mypkgs.callPackage ({ stdenv, rust }:

stdenv.mkDerivation {
  name = "smtp-server";

  buildInputs = [ ]
             ++ (with rust; [ rustc cargo ]);
}

) {
  rust = mypkgs.rustUnstable;
}
