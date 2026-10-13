#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$(mktemp -d)}
mkdir -p "$out"
export TMPDIR="$out"
cxx=${CXX:-g++}
node=${NODE:-node}
"$cxx" --version | head -1
for config in default minimal tls manual api; do
    flags=(-std=c++14 -O3 -flto -Wall -Wextra -Werror -DOBF_SEED=123456789 -pthread)
    case "$config" in
        minimal) flags+=(-DCFLOW_BRANCHING=0 -DCFLOW_CONST_DECRYPTION=0 -DCFLOW_ASM_JUNK=0 -DJUNK_ASM=0 -DVAULT_CHECK=0);;
        tls) flags+=(-DCONST_ENCRYPT_MODE=1);;
        manual) flags+=(-DIMPORT_RESOLVER=1);;
        api) flags+=(-DIMPORT_RESOLVER=2);;
    esac
    for source in selftest hardening leak_probe polymorphism asm_regression; do
        exe="$out/$config-$source"
        "$cxx" "${flags[@]}" "$repo/tests/$source.cpp" -ldl -o "$exe"
        timeout 30 "$exe" > "$exe.run.log"
        if [[ "$source" == leak_probe ]]; then
            "$node" "$repo/tests/scan_plaintext.mjs" "$exe"
        fi
    done
    echo "$config: behavior, concurrency and plaintext scan PASS"
done
for style in gnu sysv; do
    "$cxx" -shared -fPIC -Wl,--hash-style="$style" "$repo/tests/resolver_fixture.cpp" -o "$out/libobf-$style.so"
done
"$cxx" -std=c++14 -O2 -Wall -Wextra -Werror "$repo/tests/elf_resolver.cpp" -ldl -o "$out/elf-resolver"
"$out/elf-resolver" "$out/libobf-gnu.so" "$out/libobf-sysv.so"
"$cxx" -std=c++14 -O2 -Wall -Wextra -Werror -DIMPORT_RESOLVER=2 "$repo/tests/elf_resolver.cpp" -ldl -o "$out/elf-resolver-api"
"$out/elf-resolver-api" "$out/libobf-gnu.so" "$out/libobf-sysv.so"
echo "Artifacts: $out"
