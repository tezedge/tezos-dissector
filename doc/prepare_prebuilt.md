# Building

## Update

```
git pull origin master
```

## Build in docker for Linux

```
docker build -t wireshark-plugin-builder:ubuntu-19.10 -f prebuilt/plugin-builder.ubuntu-19.10.dockerfile .
docker cp (docker create wireshark-plugin-builder:ubuntu-19.10):/usr/local/tezos-dissector/target/release/libtezos_dissector.so prebuilt/libtezos_dissector_linux_3_0.so
docker build -t wireshark-plugin-builder:ubuntu-20.04 -f prebuilt/plugin-builder.ubuntu-20.04.dockerfile .
docker cp (docker create wireshark-plugin-builder:ubuntu-20.04):/usr/local/tezos-dissector/target/release/libtezos_dissector.so prebuilt/libtezos_dissector_linux_3_2.so
```

## Build on mac

Check the version of the wireshark. And then:

```
cargo build --release && cp target/release/libtezos_dissector.dylib prebuilt/libtezos_dissector_macos_3_2.dylib
```

Replace 3_2 with the version.
