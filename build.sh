#!/usr/bin/env bash

# set -e

# Map of arch and compilers to build with
declare -A compilers=(
    ["darwin/arm64"]="oa64-clang/oa64-clang++"
    ["darwin/amd64"]="o64-clang/o64-clang++"
    ["linux/arm64"]="aarch64-linux-gnu-gcc/aarch64-linux-gnu-g++"
    ["linux/amd64"]="x86_64-linux-gnu-gcc/x86_64-linux-gnu-g++"
)

# Loop through compilers list and build
for arch in "${!compilers[@]}"; do
  IFS='/' read -ra compiler <<< ${compilers[$arch]}
  echo "Building for $arch using c ${compiler[0]} and c++ ${compiler[1]}"
  rm mcl/lib/* mcl/obj/*
  docker run --entrypoint bash -v `PWD`/mcl:/mcl ghcr.io/goreleaser/goreleaser-cross:v1.19.5 -c "cd /mcl && make -j4 CC=${compiler[0]} CPP=${compiler[1]}"
  mkdir -p mclherumi/lib/$arch
  cp -f mcl/lib/libmcl.a mclherumi/lib/$arch/libmcl.a
  cp -f mcl/lib/libmclbn256.a mclherumi/lib/$arch/libmclbn256.a
done
