# Fuzzing

The fuzzing is done by cargo-fuzz. Install it:

```
cargo install cargo-fuzz
```

## Targets

This example run fuzz with 6 threads.

There are three fuzz targets.

### Random foreign traffic

```
cargo fuzz run --jobs 6 simulate_foreign
```

### One packet is one chunk

Used to simulate connection messages. It provides correctly formatted chunk in single packet. 

```
cargo fuzz run --jobs 6 simulate_handshake
```

### Encrypted conversation

Used to check decoding. It provides correct connection messages and correctly encrypted chunks. 

```
cargo fuzz run --jobs 6 simulate_encrypted
```
