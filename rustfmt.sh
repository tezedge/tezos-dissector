#!/usr/bin/env sh

rustfmt +nightly {{,wireshark-epan-adapter/}{build,src/lib},install}.rs
