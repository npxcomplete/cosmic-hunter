#!/usr/bin/env bash
# Downloads the FSR 4 v07 INT8/DOT4 asset set (SPIR-V passes, model initializers, pre-pass
# weights) used by the FSR-Vulkan provider into fsr4_shaders/. The assets were built by
# Q2RTX from AMD's MIT-licensed FidelityFX SDK FSR 4 source (see LICENSE-FSR4-v07.txt);
# they are not part of this repository. Output 1920x1080 needs the 1080 tier, 1440p and 2160p
# outputs (menu: output resolution) the 2160 tier; BB_FSR4_TIERS selects them.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
commit=ae8d628fae208813172446d1e49ed94150b04658
base="https://raw.githubusercontent.com/FireBurn/Q2RTX/$commit/baseq2/fsr4_shaders"
dest=fsr4_shaders
mkdir -p "$dest"
files=(LICENSE-FSR4-v07.txt rcas.spv spd_auto_exposure.spv)
for model in native quality balanced performance ultraperf drs; do
    files+=("fsr4_model_v07_i8_${model}_initializers.bin"
            "fsr4_model_v07_i8_${model}_pre_weights.bin"
            "fsr4_model_v07_i8_${model}_shader_manifest.json")
    for tier in ${BB_FSR4_TIERS:-1080 2160}; do
        files+=("fsr4_model_v07_i8_${model}_${tier}_pre.spv"
                "fsr4_model_v07_i8_${model}_${tier}_post.spv")
        for pass in $(seq 1 12); do
            files+=("fsr4_model_v07_i8_${model}_${tier}_pass${pass}.spv")
        done
    done
done
# Every file must match scripts/fsr4_assets.sha256 (the hashes at the pinned commit): a file
# changed on the way or on the server is deleted, never used.
manifest=scripts/fsr4_assets.sha256
expected() { awk -v name="$1" '$1 !~ /^#/ && $2 == name { print $1 }' "$manifest"; }
matches() { [[ -n $2 && $(sha256sum "$1" | cut -d' ' -f1) == "$2" ]]; }
fetched=0
for file in "${files[@]}"; do
    hash=$(expected "$file")
    if [[ -z $hash ]]; then echo "FSR 4 assets: $file is not in $manifest" >&2; exit 1; fi
    if [[ -s $dest/$file ]] && matches "$dest/$file" "$hash"; then continue; fi
    curl -fsSL --retry 3 -o "$dest/$file.part" "$base/$file"
    if ! matches "$dest/$file.part" "$hash"; then
        rm -f "$dest/$file.part"
        echo "FSR 4 assets: $file does not match its SHA-256 in $manifest" >&2
        exit 1
    fi
    mv "$dest/$file.part" "$dest/$file"
    fetched=$((fetched + 1))
done
echo "FSR 4 assets: ${#files[@]} files in $PWD/$dest ($fetched downloaded)"
# Faster, bit-exact post passes (fsr4_shaders/opt), when spirv-cross and glslang are available.
if command -v spirv-cross >/dev/null && command -v glslangValidator >/dev/null; then
    bash tools/fsr4_optimize.sh
fi
