#!/usr/bin/env bash

function ok {
    echo OK
}

function fail {
    echo FAILED
    exit 1
}

echo 'checking if there are no error messages'
./target/out/bin/tshark \
    -o tezos.identity_json_file:data/identity.json \
    -Vr data/cap-09.pcap | grep 'Decryption error' \
    >/dev/null 2>/dev/null && fail || ok
