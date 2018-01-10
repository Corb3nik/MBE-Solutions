#!/usr/bin/env bash

for f in `seq 1 100`; do echo "%$f\$x" | ./lab4C; done | grep "does not have" | cut -d " " -f1
