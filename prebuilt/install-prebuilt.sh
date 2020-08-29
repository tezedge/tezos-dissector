#!/usr/bin/env bash

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    mkdir -p ~/.local/lib/wireshark/plugins/3.2/epan/ && \
    pushd ~/.local/lib/wireshark/plugins/3.2/epan/ && \
    wget https://raw.githubusercontent.com/vlad9486/tezos-dissector/master/prebuilt/tezos_dissector_ubuntu_19_04.so; \
    mv tezos_dissector_ubuntu_19_04.so tezos_dissector.so; \
    popd
elif [[ "$OSTYPE" == "darwin"* ]]; then
    pushd /Applications/Wireshark.app/Contents/PlugIns/wireshark/3-2/epan/ && \
    wget https://raw.githubusercontent.com/vlad9486/tezos-dissector/master/prebuilt/tezos_dissector_macos.dylib && \
    mv tezos_dissector_macos.dylib tezos_dissector.so; \
    popd
else
    echo 'OS not supported'
fi
