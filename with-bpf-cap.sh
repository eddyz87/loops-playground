#!/bin/bash

sudo setpriv --reuid $(id -nu) --regid $(id -ng) --init-groups \
     --inh-caps +bpf \
     -- "$@"
