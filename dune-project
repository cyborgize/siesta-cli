(lang dune 2.9)

(name siesta)

(generate_opam_files true)

(version 1.0)

(source
 (github cyborgize/siesta-cli))

(authors "Raman Varabets <raman+opam.siesta-cli@cyborgize.sg>")

(maintainers "Raman Varabets <raman+opam.siesta-cli@cyborgize.sg>")

(license GPL-3.0-or-later)

(documentation https://github.com/cyborgize/siesta-cli)

(package
 (name siesta)
 (synopsis "Call REST APIs without a hassle")
 (description "Call REST APIs without a hassle.")
 (depends ocaml dune base64 cmdliner devkit extlib lwt lwt_ppx)
 (tags
  (api rest cli "command line")))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project
