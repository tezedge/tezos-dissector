#!/usr/bin/env sh

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
    -Vr data/cap-09.pcap | grep 'MAC mismatch' \
    >/dev/null 2>/dev/null && fail || ok

echo 'counting messages'
lines=$(\
./target/out/bin/tshark \
    -o tezos.identity_json_file:data/identity.json \
    -Vr data/cap-09.pcap | grep 'Decrypted data' | wc -l\
)

[ $lines -eq '33754' ] && ok || fail
