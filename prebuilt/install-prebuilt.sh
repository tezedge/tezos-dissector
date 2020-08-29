#!/usr/bin/env bash

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    mkdir -p "$(HOME)/.local/lib/wireshark/plugins/3.2/epan/" && \
    wget --https-only --secure-protocol=TLSv1_2 \
        "https://raw.githubusercontent.com/vlad9486/tezos-dissector/master/prebuilt/tezos_dissector_ubuntu_19_04.so" \
        -O "$(HOME)/.local/lib/wireshark/plugins/3.2/epan/tezos_dissector.so"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    curl --proto '=https' --tlsv1.2 --silent --show-error --fail \
        --location "https://raw.githubusercontent.com/vlad9486/tezos-dissector/master/prebuilt/tezos_dissector_macos.dylib" \
        --output "/Applications/Wireshark.app/Contents/PlugIns/wireshark/3-2/epan/tezos_dissector.so"
else
    echo 'OS not supported'
fi
