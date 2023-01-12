#!/usr/bin/env bash

# Map of arch and compilers to build with
declare -A compilers=(
    ["darwin/arm64"]="o64-clang/o64-clang++"
    ["darwin/amd64"]="oa64-clang/oa64-clang++"
    ["linux/arm64"]="aarch64-linux-gnu-gcc/aarch64-linux-gnu-g++"
    ["linux/amd64"]="x86_64-linux-gnu-gcc/x86_64-linux-gnu-g++"
)

# Loop through compilers list and build
for arch in "${!compilers[@]}"; do
  echo "Building for $arch"
  compiler=$(echo $compilers[$arch] | tr "/")
  rm mcl/lib/*
  docker run --entrypoint bash -v `PWD`/mcl:/mcl ghcr.io/goreleaser/goreleaser-cross:v1.19.5 -c "cd /mcl && make -j4 CC=$compiler[0] CPP=$compiler[1]"
  mkdir -p mclherumi/lib/$arch
  cp mcl/lib/libmcl.a mclherumi/lib/$arch/libmcl.a
  cp mcl/lib/libmclbn256.a mclherumi/lib/$arch/libmclbn256.a
done
