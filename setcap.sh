#!/usr/bin/env sh

setcap cap_net_raw,cap_net_admin=eip target/out/bin/dumpcap
