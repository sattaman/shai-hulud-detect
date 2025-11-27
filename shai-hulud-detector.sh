#!/bin/bash

# Shai-Hulud NPM Supply Chain Attack Detection Script
# Optimized for performance with parallel processing and smart file categorization

set -eo pipefail

TEMP_DIR=""
high_risk=0
medium_risk=0

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

PARALLELISM=4
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  PARALLELISM=$(nproc)
elif [[ "$OSTYPE" == "darwin"* ]]; then
  PARALLELISM=$(sysctl -n hw.ncpu)
fi

# Known malicious file hashes
MALICIOUS_HASHES=(
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6"
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3"
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e"
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c"
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
    "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b"
    "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee"
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"
)

create_temp_dir() {
    local temp_base="${TMPDIR:-${TMP:-${TEMP:-/tmp}}}"
    TEMP_DIR=$(mktemp -d -t shai-hulud-detect-XXXXXX 2>/dev/null || mktemp -d 2>/dev/null || echo "$temp_base/shai-hulud-detect-$$-$(date +%s)")
    mkdir -p "$TEMP_DIR" || { echo "Error: Cannot create temporary directory"; exit 1; }
    
    # File lists from single find pass
    touch "$TEMP_DIR/all_js_files.txt"
    touch "$TEMP_DIR/all_package_json.txt"
    touch "$TEMP_DIR/all_workflow_files.txt"
    touch "$TEMP_DIR/all_lockfiles.txt"
    
    # Findings
    touch "$TEMP_DIR/workflow_files.txt"
    touch "$TEMP_DIR/malicious_hashes.txt"
    touch "$TEMP_DIR/compromised_found.txt"
    touch "$TEMP_DIR/suspicious_found.txt"
    touch "$TEMP_DIR/suspicious_content.txt"
    touch "$TEMP_DIR/crypto_patterns.txt"
    touch "$TEMP_DIR/git_branches.txt"
    touch "$TEMP_DIR/postinstall_hooks.txt"
    touch "$TEMP_DIR/trufflehog_activity.txt"
    touch "$TEMP_DIR/shai_hulud_repos.txt"
    touch "$TEMP_DIR/namespace_warnings.txt"
    touch "$TEMP_DIR/low_risk_findings.txt"
    touch "$TEMP_DIR/integrity_issues.txt"
    touch "$TEMP_DIR/lockfile_safe_versions.txt"
    touch "$TEMP_DIR/bun_attack_files.txt"
    touch "$TEMP_DIR/new_workflow_files.txt"
    touch "$TEMP_DIR/github_runners.txt"
    touch "$TEMP_DIR/destructive_patterns.txt"
}

cleanup_temp_files() {
    local exit_code=$?
    [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    exit $exit_code
}

trap cleanup_temp_files EXIT INT TERM

print_status() {
    echo -e "${1}${2}${NC}"
}

usage() {
    echo "Usage: $0 [--paranoid] [--parallelism N] <directory_to_scan>"
    echo ""
    echo "OPTIONS:"
    echo "  --paranoid         Enable additional security checks"
    echo "  --parallelism N    Set threads (current: ${PARALLELISM})"
    exit 1
}

load_compromised_packages() {
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local packages_file="$script_dir/compromised-packages.txt"

    COMPROMISED_PACKAGES=()
    
    if [[ -f "$packages_file" ]]; then
        while IFS= read -r line; do
            line="${line%$'\r'}"
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            if [[ "$line" =~ ^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                COMPROMISED_PACKAGES+=("$line")
            fi
        done < "$packages_file"
        print_status "$BLUE" "📦 Loaded ${#COMPROMISED_PACKAGES[@]} compromised packages"
    else
        print_status "$YELLOW" "⚠️  Warning: $packages_file not found, using embedded list"
        COMPROMISED_PACKAGES=(
            "@ctrl/tinycolor:4.1.0"
            "@ctrl/tinycolor:4.1.1"
            "@ctrl/tinycolor:4.1.2"
            "@ctrl/deluge:1.2.0"
            "angulartics2:14.1.2"
            "koa2-swagger-ui:5.11.1"
            "koa2-swagger-ui:5.11.2"
        )
    fi
}

# Collect all relevant files in a single optimized pass
collect_files() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Collecting files (single optimized pass)..."
    
    # Direct find output to files with parallel execution
    find "$scan_dir" \
        \( -path "*/node_modules/.cache" -o -path "*/node_modules/.bin" -o -path "*/node_modules/.staging" \) -prune -o \
        -type f -name "package.json" -print 2>/dev/null > "$TEMP_DIR/all_package_json.txt" &
    
    find "$scan_dir" \
        \( -path "*/node_modules/.cache" -o -path "*/node_modules/.bin" -o -path "*/node_modules/.staging" \) -prune -o \
        -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -print 2>/dev/null > "$TEMP_DIR/all_lockfiles.txt" &
    
    find "$scan_dir" \
        \( -path "*/node_modules/.cache" -o -path "*/node_modules/.bin" -o -path "*/node_modules/.staging" \) -prune -o \
        -type f -name "shai-hulud-workflow.yml" -print 2>/dev/null > "$TEMP_DIR/workflow_files.txt" &
    
    find "$scan_dir" \
        \( -path "*/node_modules/.cache" -o -path "*/node_modules/.bin" -o -path "*/node_modules/.staging" \) -prune -o \
        -type f \( -name "setup_bun.js" -o -name "bun_environment.js" \) -print 2>/dev/null > "$TEMP_DIR/bun_attack_files.txt" &
    
    find "$scan_dir" \
        \( -path "*/node_modules/.cache" -o -path "*/node_modules/.bin" -o -path "*/node_modules/.staging" \) -prune -o \
        -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \) ! -name "*.d.ts" ! -name "*.map" -print 2>/dev/null > "$TEMP_DIR/all_js_files.txt" &
    
    wait
    
    local js_count=$(wc -l < "$TEMP_DIR/all_js_files.txt" 2>/dev/null | tr -d ' ')
    local pkg_count=$(wc -l < "$TEMP_DIR/all_package_json.txt" 2>/dev/null | tr -d ' ')
    print_status "$BLUE" "   Found $js_count JS/TS/JSON files, $pkg_count package.json files"
}

# Check file hashes against known malicious hashes with parallel processing
check_file_hashes_fast() {
    print_status "$BLUE" "🔍 Checking file hashes (parallel)..."
    
    [[ ! -s "$TEMP_DIR/all_js_files.txt" ]] && return
    
    local total=$(wc -l < "$TEMP_DIR/all_js_files.txt" | tr -d ' ')
    local checked=0
    
    # Parallel hash calculation
    cat "$TEMP_DIR/all_js_files.txt" | xargs -P "$PARALLELISM" -I{} sh -c '
        hash=$(shasum -a 256 "{}" 2>/dev/null | cut -d" " -f1)
        echo "{}:$hash"
    ' 2>/dev/null | while IFS=: read -r file hash; do
        # Linear search through malicious hashes
        for malicious_hash in "${MALICIOUS_HASHES[@]}"; do
            if [[ "$hash" == "$malicious_hash" ]]; then
                echo "$file:$hash" >> "$TEMP_DIR/malicious_hashes.txt"
                break
            fi
        done
        checked=$((checked + 1))
        if [[ $((checked % 100)) -eq 0 ]]; then
            echo -ne "\r   Checked $checked/$total files" >&2
        fi
    done
    echo -ne "\r\033[K" >&2
}

# Parse semantic version string into components
semverParseInto() {
    local RE='[^0-9]*\([0-9]*\)[.]\([0-9]*\)[.]\([0-9]*\)\([0-9A-Za-z-]*\)'
    printf -v "$2" '%s' "$(echo $1 | sed -e "s/$RE/\1/")"
    printf -v "$3" '%s' "$(echo $1 | sed -e "s/$RE/\2/")"
    printf -v "$4" '%s' "$(echo $1 | sed -e "s/$RE/\3/")"
    printf -v "$5" '%s' "$(echo $1 | sed -e "s/$RE/\4/")"
}

semver_match() {
    local test_subject=$1
    local test_pattern=$2
    
    [[ "*" == "${test_pattern}" ]] && return 0
    
    local subject_major=0 subject_minor=0 subject_patch=0 subject_special=0
    semverParseInto ${test_subject} subject_major subject_minor subject_patch subject_special
    
    while IFS= read -r pattern; do
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        [[ "*" == "${pattern}" ]] && return 0
        
        local pattern_major=0 pattern_minor=0 pattern_patch=0 pattern_special=0
        case "${pattern}" in
            ^*)
                semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}" == "${pattern_major}" ]] || continue
                [[ "${subject_minor}" -ge "${pattern_minor}" ]] || continue
                if [[ "${subject_minor}" == "${pattern_minor}" ]]; then
                    [[ "${subject_patch}" -ge "${pattern_patch}" ]] || continue
                fi
                return 0
                ;;
            ~*)
                semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}" == "${pattern_major}" ]] || continue
                [[ "${subject_minor}" == "${pattern_minor}" ]] || continue
                [[ "${subject_patch}" -ge "${pattern_patch}" ]] || continue
                return 0
                ;;
            *[xX]*)
                local pattern_parts subject_parts
                IFS='.' read -ra pattern_parts <<< "${pattern}"
                IFS='.' read -ra subject_parts <<< "${test_subject}"
                for i in 0 1 2; do
                    if [[ ${i} -lt ${#pattern_parts[@]} && ${i} -lt ${#subject_parts[@]} ]]; then
                        local pattern_part="${pattern_parts[i]}"
                        local subject_part="${subject_parts[i]}"
                        [[ "${pattern_part}" == "x" || "${pattern_part}" == "X" ]] && continue
                        pattern_part=$(echo "${pattern_part}" | sed 's/[^0-9].*//')
                        subject_part=$(echo "${subject_part}" | sed 's/[^0-9].*//')
                        [[ "${subject_part}" != "${pattern_part}" ]] && continue 2
                    fi
                done
                return 0
                ;;
            *)
                semverParseInto ${pattern} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}" -eq "${pattern_major}" ]] || continue
                [[ "${subject_minor}" -eq "${pattern_minor}" ]] || continue
                [[ "${subject_patch}" -eq "${pattern_patch}" ]] || continue
                [[ "${subject_special}" == "${pattern_special}" ]] || continue
                return 0
                ;;
        esac
    done < <(echo "${test_pattern}" | sed 's/||/\n/g')
    return 1
}

# Get package version from nearest lockfile
get_lockfile_version_cached() {
    local package_name="$1"
    local package_dir="$2"
    
    # Find nearest lockfile
    local current_dir="$package_dir"
    while [[ "$current_dir" != "/" && -n "$current_dir" ]]; do
        if [[ -f "$current_dir/package-lock.json" ]]; then
            local version=$(awk -v pkg="node_modules/$package_name" '
                $0 ~ "\"" pkg "\":" { in_block=1; brace_count=1 }
                in_block && /\{/ && !($0 ~ "\"" pkg "\":") { brace_count++ }
                in_block && /\}/ { brace_count--; if (brace_count <= 0) in_block=0 }
                in_block && /\s*"version":/ {
                    split($0, parts, "\"")
                    for (i in parts) {
                        if (parts[i] ~ /^[0-9]/) { print parts[i]; exit }
                    }
                }
            ' "$current_dir/package-lock.json" 2>/dev/null)
            echo "$version"
            return
        fi
        current_dir=$(dirname "$current_dir")
    done
    echo ""
}

check_packages_fast() {
    print_status "$BLUE" "🔍 Checking packages..."
    
    [[ ! -s "$TEMP_DIR/all_package_json.txt" ]] && return
    
    while IFS= read -r package_file; do
        [[ ! -r "$package_file" ]] && continue
        
        # Extract dependencies in one pass
        awk '/"dependencies":|"devDependencies":/{flag=1;next}/}/{flag=0}flag' "$package_file" | \
        grep -o '"[^"]*"[[:space:]]*:[[:space:]]*"[^"]*"' 2>/dev/null | while IFS= read -r line; do
            local pkg_name=$(echo "$line" | cut -d'"' -f2)
            local pkg_version=$(echo "$line" | cut -d'"' -f4)
            
            # Check against compromised packages
            for malicious_info in "${COMPROMISED_PACKAGES[@]}"; do
                local mal_name="${malicious_info%:*}"
                local mal_version="${malicious_info#*:}"
                
                [[ "$pkg_name" != "$mal_name" ]] && continue
                
                # Exact match
                if [[ "$pkg_version" == "$mal_version" ]]; then
                    echo "$package_file:$pkg_name@$pkg_version" >> "$TEMP_DIR/compromised_found.txt"
                    continue 2
                fi
                
                # Semver pattern matching
                if semver_match "$mal_version" "$pkg_version"; then
                    local actual_version=$(get_lockfile_version_cached "$pkg_name" "$(dirname "$package_file")")
                    if [[ -n "$actual_version" ]]; then
                        if [[ "$actual_version" == "$mal_version" ]]; then
                            echo "$package_file:$pkg_name@$actual_version" >> "$TEMP_DIR/compromised_found.txt"
                        else
                            echo "$package_file:$pkg_name@$pkg_version (locked to $actual_version - safe)" >> "$TEMP_DIR/lockfile_safe_versions.txt"
                        fi
                    else
                        echo "$package_file:$pkg_name@$pkg_version" >> "$TEMP_DIR/suspicious_found.txt"
                    fi
                fi
            done
        done
        
        # Check postinstall hooks
        if grep -q '"postinstall"' "$package_file" 2>/dev/null; then
            local cmd=$(grep -A1 '"postinstall"' "$package_file" | grep -o '"[^"]*"' | tail -1 | tr -d '"')
            if [[ "$cmd" == *"curl"* || "$cmd" == *"wget"* || "$cmd" == *"eval"* || "$cmd" == *"node -e"* ]]; then
                echo "$package_file:Suspicious postinstall: $cmd" >> "$TEMP_DIR/postinstall_hooks.txt"
            fi
        fi
        
        # Check for fake Bun preinstall
        if grep -q '"preinstall"[[:space:]]*:[[:space:]]*"node setup_bun\.js"' "$package_file" 2>/dev/null; then
            echo "$package_file" >> "$TEMP_DIR/bun_attack_files.txt"
        fi
    done < "$TEMP_DIR/all_package_json.txt"
}

# Scan content for suspicious patterns with parallel processing
check_content_patterns_fast() {
    print_status "$BLUE" "🔍 Checking content patterns..."
    
    [[ ! -s "$TEMP_DIR/all_js_files.txt" ]] && return
    
    # Single parallel grep for multiple patterns
    cat "$TEMP_DIR/all_js_files.txt" | xargs -P "$PARALLELISM" grep -l -E \
        'webhook\.site|bb8ca5f6-4175-45d2-b042-fc9ebb8170b7|0x[a-fA-F0-9]{40}|XMLHttpRequest\.prototype\.send|trufflehog|TruffleHog|AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|SHA1HULUD' \
        2>/dev/null | while IFS= read -r file; do
        
        # Categorize findings
        if grep -q 'webhook\.site\|bb8ca5f6-4175-45d2-b042-fc9ebb8170b7' "$file" 2>/dev/null; then
            echo "$file:webhook.site reference" >> "$TEMP_DIR/suspicious_content.txt"
        fi
        
        if grep -q '0x[a-fA-F0-9]\{40\}' "$file" 2>/dev/null; then
            if grep -q -E 'ethereum|wallet|crypto' "$file" 2>/dev/null; then
                echo "$file:Ethereum wallet patterns" >> "$TEMP_DIR/crypto_patterns.txt"
            fi
        fi
        
        if grep -q 'XMLHttpRequest\.prototype\.send' "$file" 2>/dev/null; then
            if [[ "$file" == *"/react-native/"* || "$file" == *"/next/dist/"* ]]; then
                if grep -q -E '0x[a-fA-F0-9]{40}|webhook\.site' "$file" 2>/dev/null; then
                    echo "$file:XMLHttpRequest with crypto - HIGH RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                fi
            else
                echo "$file:XMLHttpRequest modification" >> "$TEMP_DIR/crypto_patterns.txt"
            fi
        fi
        
        if grep -q 'trufflehog\|TruffleHog' "$file" 2>/dev/null; then
            if [[ "$file" != *".md" && "$file" != *".txt" ]]; then
                if grep -q 'subprocess.*curl\|download.*trufflehog' "$file" 2>/dev/null; then
                    echo "$file:HIGH:Suspicious trufflehog execution" >> "$TEMP_DIR/trufflehog_activity.txt"
                else
                    echo "$file:MEDIUM:Trufflehog reference" >> "$TEMP_DIR/trufflehog_activity.txt"
                fi
            fi
        fi
        
        if grep -q 'SHA1HULUD' "$file" 2>/dev/null; then
            echo "$file" >> "$TEMP_DIR/github_runners.txt"
        fi
    done
}

# Check git repositories for suspicious branches and names
check_git_fast() {
    print_status "$BLUE" "🔍 Checking git repositories..."
    
    find "$1" -name ".git" -type d 2>/dev/null | while IFS= read -r git_dir; do
        local repo_dir=$(dirname "$git_dir")
        
        # Check branches
        if [[ -d "$git_dir/refs/heads" ]]; then
            find "$git_dir/refs/heads" -name "*shai-hulud*" -type f 2>/dev/null | while IFS= read -r branch; do
                local name=$(basename "$branch")
                local hash=$(cat "$branch" 2>/dev/null | head -c 8)
                echo "$repo_dir:Branch '$name' ($hash...)" >> "$TEMP_DIR/git_branches.txt"
            done
        fi
        
        # Check repo name
        local repo_name=$(basename "$repo_dir")
        if [[ "$repo_name" == *"shai-hulud"* || "$repo_name" == *"-migration"* ]]; then
            echo "$repo_dir:Suspicious repo name: $repo_name" >> "$TEMP_DIR/shai_hulud_repos.txt"
        fi
        
        # Check for data.json (exfiltration)
        if [[ -f "$repo_dir/data.json" ]]; then
            if head -5 "$repo_dir/data.json" 2>/dev/null | grep -q 'eyJ.*=='; then
                echo "$repo_dir:Suspicious data.json (base64)" >> "$TEMP_DIR/shai_hulud_repos.txt"
            fi
        fi
    done
}

# Check GitHub Actions workflows for malicious patterns
check_workflows_fast() {
    print_status "$BLUE" "🔍 Checking GitHub Actions workflows..."
    
    find "$1" -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" 2>/dev/null | while IFS= read -r file; do
        local basename=$(basename "$file")
        
        # Known malicious filenames
        if [[ "$basename" == "shai-hulud-workflow.yml" || "$basename" == formatter_*.yml ]]; then
            echo "$file" >> "$TEMP_DIR/workflow_files.txt"
        fi
        
        # Discussion triggers
        if grep -q 'on:.*discussion\|on:\s*discussion' "$file" 2>/dev/null; then
            echo "$file:Discussion trigger" >> "$TEMP_DIR/workflow_files.txt"
        fi
        
        # SHA1HULUD runners
        if grep -q 'SHA1HULUD' "$file" 2>/dev/null; then
            echo "$file" >> "$TEMP_DIR/github_runners.txt"
        fi
    done
}

# Check for destructive command patterns
check_destructive_fast() {
    print_status "$BLUE" "🔍 Checking for destructive patterns..."
    
    find "$1" -type f \( -name "*.js" -o -name "*.sh" -o -name "*.ps1" \) 2>/dev/null | head -1000 | \
    xargs -P "$PARALLELISM" grep -l -E 'rm -rf \$HOME|rm -rf ~|fs\.rmSync.*recursive|Remove-Item -Recurse' 2>/dev/null | \
    while IFS= read -r file; do
        echo "$file:Destructive pattern detected" >> "$TEMP_DIR/destructive_patterns.txt"
    done
}

# Convert pnpm-lock.yaml to pseudo-package-lock.json format for parsing
transform_pnpm_yaml() {
    declare -a path
    packages_file=$1

    echo -e "{"
    echo -e "  \"packages\": {"

    depth=0
    while IFS= read -r line; do

        # Find indentation
        sep="${line%%[^ ]*}"
        currentdepth="${#sep}"

        # Remove surrounding whitespace
        line=${line##*( )} # From the beginning
        line=${line%%*( )} # From the end

        # Remove comments
        line=${line%%#*}
        line=${line%%*( )}

        # Remove comments and empty lines
        if [[ "${line:0:1}" == '#' ]] || [[ "${#line}" == 0 ]]; then
            continue
        fi

        # split into key/val
        key=${line%%:*}
        key=${key%%*( )}
        val=${line#*:}
        val=${val##*( )}

        # Save current path
        path[$currentdepth]=$key

        # Interested in packages.*
        if [ "${path[0]}" != "packages" ]; then continue; fi
        if [ "${currentdepth}" != "2" ]; then continue; fi

        # Remove surrounding whitespace (yes, again)
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"

        # Remove quote
        key="${key#"${key%%[!\']*}"}"
        key="${key%"${key##*[!\']}"}"

        # split into name/version
        name=${key%\@*}
        name=${name%*( )}
        version=${key##*@}
        version=${version##*( )}

        echo "    \"${name}\": {"
        echo "      \"version\": \"${version}\""
        echo "    },"

    done < "$packages_file"
    echo "  }"
    echo "}"
}

# Verify package lock files for compromised packages and version integrity
check_package_integrity() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking package lock files for integrity issues..."

    # Check package-lock.json files
    while IFS= read -r -d '' lockfile; do
        if [[ -f "$lockfile" && -r "$lockfile" ]]; then

            # Transform pnpm-lock.yaml into pseudo-package-lock
            org_file="$lockfile"
            if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
                org_file="$lockfile"
                lockfile=$(mktemp "${TMPDIR:-/tmp}/lockfile.XXXXXXXX")
                transform_pnpm_yaml "$org_file" > "$lockfile"
            fi

            # Look for compromised packages in lockfiles
            for package_info in "${COMPROMISED_PACKAGES[@]}"; do
                local package_name="${package_info%:*}"
                local malicious_version="${package_info#*:}"

                # Look for package-specific blocks to avoid version misattribution
                local found_version=""

                # Try to find the package in node_modules structure (most accurate for package-lock.json)
                if grep -q "\"node_modules/$package_name\"" "$lockfile" 2>/dev/null; then
                    # Extract version from within the specific package block
                    found_version=$(awk -v pkg="node_modules/$package_name" '
                        $0 ~ "\"" pkg "\"" { in_block=1; brace_count=1 }
                        in_block && /\{/ && !($0 ~ "\"" pkg "\"") { brace_count++ }
                        in_block && /\}/ {
                            brace_count--
                            if (brace_count <= 0) { in_block=0 }
                        }
                        in_block && /\s*"version":/ {
                            gsub(/.*"version"[ \t]*:[ \t]*"/, "", $0)
                            gsub(/".*/, "", $0)
                            print $0
                            exit
                        }
                    ' "$lockfile" 2>/dev/null || true) || true

                # Fallback: for older lockfile formats without node_modules structure
                # Only look for exact version matches on the same line
                elif grep -q "\"$package_name\".*:.*\"[0-9]" "$lockfile" 2>/dev/null; then
                    # Extract version from same line (for simple dependency format)
                    found_version=$(grep "\"$package_name\".*:.*\"[0-9]" "$lockfile" 2>/dev/null | head -1 | awk -F':' '{
                        gsub(/.*"/, "", $2)
                        gsub(/".*/, "", $2)
                        print $2
                    }' 2>/dev/null || true) || true
                fi

                if [[ -n "$found_version" && "$found_version" == "$malicious_version" ]]; then
                    echo "$org_file:Compromised package in lockfile: $package_name@$malicious_version" >> "$TEMP_DIR/integrity_issues.txt"
                fi
            done

            # Check for suspicious integrity hash patterns (may indicate tampering)
            local suspicious_hashes
            suspicious_hashes=$(grep -c '"integrity": "sha[0-9]\+-[A-Za-z0-9+/=]*"' "$lockfile" 2>/dev/null || echo "0")

            # Check for recently modified lockfiles with @ctrl packages (potential worm activity)
            if grep -q "@ctrl" "$lockfile" 2>/dev/null; then
                local file_age
                file_age=$(date -r "$lockfile" +%s 2>/dev/null || echo "0")
                local current_time
                current_time=$(date +%s)
                local age_diff=$((current_time - file_age))

                # Flag if lockfile with @ctrl packages was modified in the last 30 days
                if [[ $age_diff -lt 2592000 ]]; then  # 30 days in seconds
                    echo "$org_file:Recently modified lockfile contains @ctrl packages (potential worm activity)" >> "$TEMP_DIR/integrity_issues.txt"
                fi
            fi

            # Revert virtual package-lock
            if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
                rm "$lockfile"
                lockfile="$org_file"
            fi

        fi
    done < <(find "$scan_dir" \( -name "pnpm-lock.yaml" -o -name "yarn.lock" -o -name "package-lock.json" \) -print0 2>/dev/null || true)
}

generate_report() {
    echo
    print_status "$BLUE" "=============================================="
    print_status "$BLUE" "      SHAI-HULUD DETECTION REPORT"
    print_status "$BLUE" "=============================================="
    echo
    
    high_risk=0
    medium_risk=0
    
    # Malicious workflows
    if [[ -s "$TEMP_DIR/workflow_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Malicious workflow files:"
        while IFS= read -r file; do
            echo "   - $file"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/workflow_files.txt"
        echo
    fi
    
    # Malicious hashes
    if [[ -s "$TEMP_DIR/malicious_hashes.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Files with known malicious hashes:"
        while IFS=: read -r file hash; do
            echo "   - $file"
            echo "     Hash: $hash"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/malicious_hashes.txt"
        echo
    fi
    
    # Bun attack files
    if [[ -s "$TEMP_DIR/bun_attack_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: November 2025 Bun attack files:"
        while IFS= read -r file; do
            echo "   - $file"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/bun_attack_files.txt"
        echo
    fi
    
    # Compromised packages
    if [[ -s "$TEMP_DIR/compromised_found.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Compromised packages:"
        while IFS=: read -r file pkg; do
            echo "   - Package: $pkg"
            echo "     Found in: $file"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/compromised_found.txt"
        echo
    fi
    
    # Suspicious postinstall
    if [[ -s "$TEMP_DIR/postinstall_hooks.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Suspicious postinstall hooks:"
        while IFS=: read -r file hook; do
            echo "   - $file"
            echo "     Hook: $hook"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/postinstall_hooks.txt"
        echo
    fi
    
    # Trufflehog HIGH risk
    if [[ -s "$TEMP_DIR/trufflehog_activity.txt" ]]; then
        grep "^.*:HIGH:" "$TEMP_DIR/trufflehog_activity.txt" 2>/dev/null | while IFS=: read -r file level activity; do
            if [[ "$level" == "HIGH" ]]; then
                print_status "$RED" "🚨 HIGH RISK: Trufflehog activity:"
                echo "   - $file"
                echo "     Activity: $activity"
                high_risk=$((high_risk+1))
            fi
        done
    fi
    
    # Shai-Hulud repos
    if [[ -s "$TEMP_DIR/shai_hulud_repos.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Shai-Hulud repositories:"
        while IFS=: read -r repo info; do
            echo "   - $repo"
            echo "     $info"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/shai_hulud_repos.txt"
        echo
    fi
    
    # GitHub runners
    if [[ -s "$TEMP_DIR/github_runners.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: SHA1HULUD runners detected:"
        while IFS= read -r file; do
            echo "   - $file"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/github_runners.txt"
        echo
    fi
    
    # Destructive patterns
    if [[ -s "$TEMP_DIR/destructive_patterns.txt" ]]; then
        print_status "$RED" "🚨 CRITICAL: Destructive patterns:"
        while IFS=: read -r file pattern; do
            echo "   - $file"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/destructive_patterns.txt"
        echo
    fi
    
    # Package integrity issues
    if [[ -s "$TEMP_DIR/integrity_issues.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Package integrity issues:"
        while IFS=: read -r file issue; do
            echo "   - $file"
            echo "     $issue"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/integrity_issues.txt"
        echo
    fi
    
    # MEDIUM RISK
    if [[ -s "$TEMP_DIR/suspicious_found.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious packages:"
        while IFS=: read -r file pkg; do
            echo "   - $pkg (in $file)"
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/suspicious_found.txt"
        echo
    fi
    
    if [[ -s "$TEMP_DIR/suspicious_content.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious content:"
        while IFS=: read -r file pattern; do
            echo "   - $file: $pattern"
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/suspicious_content.txt"
        echo
    fi
    
    if [[ -s "$TEMP_DIR/crypto_patterns.txt" ]]; then
        local has_high=0
        grep -q "HIGH RISK" "$TEMP_DIR/crypto_patterns.txt" && has_high=1
        
        if [[ $has_high -eq 1 ]]; then
            print_status "$RED" "🚨 HIGH RISK: Crypto theft patterns:"
            grep "HIGH RISK" "$TEMP_DIR/crypto_patterns.txt" | while IFS=: read -r file pattern; do
                echo "   - $file"
                high_risk=$((high_risk+1))
            done
            echo
        fi
        
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Crypto patterns:"
        grep -v "HIGH RISK" "$TEMP_DIR/crypto_patterns.txt" | while IFS=: read -r file pattern; do
            echo "   - $file"
            medium_risk=$((medium_risk+1))
        done
        echo
    fi
    
    if [[ -s "$TEMP_DIR/git_branches.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious git branches:"
        while IFS=: read -r repo branch; do
            echo "   - $repo: $branch"
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/git_branches.txt"
        echo
    fi
    
    # LOW RISK
    if [[ -s "$TEMP_DIR/lockfile_safe_versions.txt" ]]; then
        print_status "$BLUE" "ℹ️  LOW RISK: Lockfile-protected packages:"
        local count=$(wc -l < "$TEMP_DIR/lockfile_safe_versions.txt" | tr -d ' ')
        echo "   $count packages with safe lockfile versions"
        echo "   (Your current installation is safe, avoid 'npm update')"
        echo
    fi
    
    local total=$((high_risk + medium_risk))
    
    print_status "$BLUE" "=============================================="
    if [[ $total -eq 0 ]]; then
        print_status "$GREEN" "✅ No indicators of Shai-Hulud compromise detected."
        print_status "$GREEN" "Your system appears clean."
    else
        print_status "$RED" "🔍 SUMMARY:"
        print_status "$RED" "   High Risk: $high_risk"
        print_status "$YELLOW" "   Medium Risk: $medium_risk"
        print_status "$BLUE" "   Total: $total"
    fi
    print_status "$BLUE" "=============================================="
}

main() {
    local paranoid_mode=false
    local scan_dir=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --paranoid) paranoid_mode=true ;;
            --parallelism)
                PARALLELISM=$2
                shift
                ;;
            --help|-h) usage ;;
            -*) echo "Unknown option: $1"; usage ;;
            *)
                [[ -z "$scan_dir" ]] && scan_dir="$1" || { echo "Too many arguments"; usage; }
                ;;
        esac
        shift
    done
    
    [[ -z "$scan_dir" ]] && usage
    [[ ! -d "$scan_dir" ]] && { print_status "$RED" "Error: Directory not found"; exit 1; }
    
    scan_dir=$(cd "$scan_dir" && pwd)
    
    print_status "$GREEN" "Starting Shai-Hulud detection..."
    print_status "$BLUE" "Scanning: $scan_dir (parallelism: $PARALLELISM)"
    echo
    
    load_compromised_packages
    create_temp_dir
    
    # Single file collection pass
    collect_files "$scan_dir"
    
    # Parallel detection
    check_file_hashes_fast &
    check_packages_fast &
    check_content_patterns_fast &
    check_git_fast "$scan_dir" &
    check_workflows_fast "$scan_dir" &
    check_destructive_fast "$scan_dir" &
    check_package_integrity "$scan_dir" &
    
    wait
    
    generate_report
    
    [[ $high_risk -gt 0 ]] && exit 1
    [[ $medium_risk -gt 0 ]] && exit 2
    exit 0
}

main "$@"

