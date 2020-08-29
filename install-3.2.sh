#!/usr/bin/env bash

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    mkdir -p ~/.local/lib/wireshark/plugins/3.2/epan/ && \
    cp target/release/libtezos_dissector.so \
    ~/.local/lib/wireshark/plugins/3.2/epan/
elif [[ "$OSTYPE" == "darwin"* ]]; then
    cp target/release/libtezos_dissector.dylib \
    /Applications/Wireshark.app/Contents/PlugIns/wireshark/3-2/epan/tezos.so
else
    echo 'OS not supported'
fi
