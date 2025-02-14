#!/bin/sh
docker build -t rust-cc .
docker run --rm -v $(pwd):/generation -w /generation rust-cc cargo build -r
