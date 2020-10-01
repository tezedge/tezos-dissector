#!/usr/bin/env sh

rustfmt +nightly {{,wireshark-epan-adapter/}{build,src/lib},tezos-conversation/src/lib,wireshark-epan-adapter/examples/*}.rs
