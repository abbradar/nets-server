{ mypkgs ? import /home/shlomo/cgate { } }:

mypkgs.callPackage ({ stdenv, pkgconfig, rust }:

stdenv.mkDerivation {
  name = "smtp-server";

  buildInputs = [ pkgconfig ]
             ++ (with rust; [ rustc cargo ]);
}

) {
  rust = mypkgs.rustUnstable;
}
