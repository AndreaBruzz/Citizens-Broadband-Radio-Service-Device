#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
owned_container() {
    [[ $OWN_DEPLOYMENT == true &&
       ( $1 == "$PROJECT|$PROJECT_ID|registration-cpi-only" ||
         $1 == "$PROJECT|$PROJECT_ID|lab-positive" ) ]]
}
check_profile() {
    [[ $PROFILE == registration-cpi-only || $PROFILE == lab-positive ]] || fail "Invalid profile"
    [[ $PROFILE_EXPLICIT == true || $PROFILE_EXPLICIT == false ]] || fail "Invalid explicit-profile flag"
    [[ $PROFILE != lab-positive || $PROFILE_EXPLICIT == true ]] || fail "lab-positive must be selected explicitly"
}
check_host() {
    [[ $(uname -s) == Linux ]] || fail "Linux is required; no OS/architecture assumed"
    [[ $(id -u) == 0 ]] || fail "This deployment payload requires root"
    for tool in docker tar sha256sum flock ss find stat realpath; do
        command -v "$tool" >/dev/null || fail "$tool missing; no system packages will be installed"
    done
    docker info >/dev/null || fail "Docker daemon unavailable"
    docker compose version >/dev/null || fail "Docker Compose v2 plugin unavailable"
    local endpoint security
    endpoint=$(docker context inspect "$(docker context show)" --format '{{.Endpoints.docker.Host}}')
    [[ $endpoint == unix://* && ${DOCKER_HOST:-unix://local} == unix://* ]] || fail "Use the server's local Unix-socket Docker daemon"
    security=$(docker info --format '{{json .SecurityOptions}}')
    [[ $security != *rootless* && $security != *userns* ]] || fail "This bind deployment requires rootful Docker without userns remapping"
}

check_directory() {
    [[ $DEPLOY =~ ^/(opt|srv)/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$ ]] || fail "Unsafe deployment path"
    PROJECT_ID=$(printf '%s' "$DEPLOY" | sha256sum | cut -d ' ' -f1)
    PROJECT="winnf-mock-sas-${PROJECT_ID:0:12}"
    OWN_DEPLOYMENT=false
    [[ ! -L $DEPLOY && ! -L $DEPLOY/.deployment-owner ]] || fail "Deployment/owner path must not be a symlink"
    [[ $(realpath -m "$DEPLOY") == "$DEPLOY" ]] || fail "Deployment ancestors must not be symlinks"
    local parent=${DEPLOY%/*}
    while [[ -n $parent && $parent != / ]]; do
        if [[ -e $parent ]]; then
            [[ -d $parent && $(stat -c %u "$parent") == 0 ]] || fail "Deployment ancestor must be a root-owned directory"
            (( (8#$(stat -c %a "$parent") & 0022) == 0 )) || fail "Deployment ancestor must not be group/world writable"
        fi
        [[ $parent == */* ]] || break
        parent=${parent%/*}
    done
    if [[ -e $DEPLOY ]]; then
        [[ -d $DEPLOY ]] || fail "Deployment path is not a directory"
        [[ $(stat -c %u "$DEPLOY") == 0 ]] || fail "Deployment directory must belong to root"
        (( (8#$(stat -c %a "$DEPLOY") & 0022) == 0 )) || fail "Deployment directory must not be group/world writable"
        if [[ -f $DEPLOY/.deployment-owner ]]; then
            [[ $(cat "$DEPLOY/.deployment-owner") == "$PROJECT_ID" ]] || fail "Deployment directory belongs to another deployment"
            [[ $(stat -c %u "$DEPLOY/.deployment-owner") == 0 ]] || fail "Deployment owner marker must belong to root"
            (( (8#$(stat -c %a "$DEPLOY/.deployment-owner") & 0077) == 0 )) || fail "Deployment owner marker must be root-only"
            OWN_DEPLOYMENT=true
        else
            local contents
            contents=$(find "$DEPLOY" -mindepth 1 -maxdepth 1 -print -quit) || fail "Cannot inspect deployment directory"
            [[ -z $contents ]] || fail "Existing nonempty directory has no verified owner marker; do not adopt/overwrite it"
        fi
        if [[ -e $DEPLOY/.active-profile || -L $DEPLOY/.active-profile ]]; then
            [[ $OWN_DEPLOYMENT == true && -f $DEPLOY/.active-profile && ! -L $DEPLOY/.active-profile ]] ||
                fail "Invalid active-profile metadata"
            [[ $(stat -c %u "$DEPLOY/.active-profile") == 0 ]] || fail "Active-profile metadata must be root-owned"
            (( (8#$(stat -c %a "$DEPLOY/.active-profile") & 0077) == 0 )) || fail "Active-profile metadata must be root-only"
            local active_profile
            active_profile=$(cat "$DEPLOY/.active-profile")
            [[ $active_profile == registration-cpi-only || $active_profile == lab-positive ]] || fail "Invalid stored profile"
            [[ $active_profile == "$PROFILE" || $PROFILE_EXPLICIT == true ]] || fail "Profile changes require explicit selection"
        fi
        if [[ -e $DEPLOY/lab-state || -L $DEPLOY/lab-state ]]; then
            [[ $OWN_DEPLOYMENT == true && -d $DEPLOY/lab-state && ! -L $DEPLOY/lab-state ]] ||
                fail "Unsafe persistent state directory"
            [[ $(stat -c %u:%g:%a "$DEPLOY/lab-state") == 10001:10001:700 ]] ||
                fail "Persistent state directory must be UID/GID10001 mode700"
            local entry info
            while IFS= read -r -d '' entry; do
                [[ ${entry##*/} == session.json || ${entry##*/} == session.lock ||
                   ${entry##*/} =~ ^\.backup-[a-f0-9]{64}\.json$ ||
                   ${entry##*/} =~ ^\.session-[a-zA-Z0-9_-]+\.tmp$ ]] || fail "Unexpected persistent state content"
                if ! info=$(stat -c '%F|%u:%g:%a' "$entry" 2>/dev/null); then
                    # The active worker may have atomically committed this temporary file.
                    if [[ ${entry##*/} =~ ^\.session-[a-zA-Z0-9_-]+\.tmp$ &&
                          ! -e $entry && ! -L $entry ]]; then continue; fi
                    fail "Persistent state file disappeared or is unreadable"
                fi
                [[ $info == 'regular file|10001:10001:600' ||
                   $info == 'regular empty file|10001:10001:600' ]] ||
                    fail "Unsafe persistent state file"
            done < <(find "$DEPLOY/lab-state" -mindepth 1 -maxdepth 1 -print0)
        fi
    fi
    local containers container labels
    containers=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT") || fail "Cannot inspect project collisions"
    for container in $containers; do
        labels=$(container_identity "$container")
        owned_container "$labels" || fail "Compose project collision with unrelated container $container"
        [[ ${labels##*|} == "$PROFILE" || $PROFILE_EXPLICIT == true ]] || fail "Profile changes require explicit selection"
    done
}

container_identity() {
    docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "org.winnf.mock-sas.deployment"}}|{{index .Config.Labels "org.winnf.mock-sas.profile"}}' "$1" ||
        fail "Cannot inspect container ownership"
}

owned_proxy_listener() {
    local listener=$1 bindings=$2 pid argument found=false remaining=$1
    local -a arguments
    while [[ $remaining =~ pid=([0-9]+) ]]; do
        pid=${BASH_REMATCH[1]}
        remaining=${remaining#*pid=$pid}
        [[ -r /proc/$pid/cmdline ]] || return 1
        arguments=()
        while IFS= read -r -d '' argument; do arguments+=("$argument"); done < "/proc/$pid/cmdline"
        [[ ${#arguments[@]} -gt 0 && ${arguments[0]##*/} == docker-proxy ]] || return 1
        local host= bound= destination= target= protocol= i
        for ((i=1; i+1<${#arguments[@]}; i++)); do
            case ${arguments[i]} in
                -host-ip) host=${arguments[i+1]} ;;
                -host-port) bound=${arguments[i+1]} ;;
                -container-ip) destination=${arguments[i+1]} ;;
                -container-port) target=${arguments[i+1]} ;;
                -proto) protocol=${arguments[i+1]} ;;
            esac
        done
        [[ $protocol == tcp && -n $host && -n $destination && -n $bound && -n $target ]] || return 1
        [[ $'\n'$bindings$'\n' == *$'\n'"$host|$bound|$destination|$target"$'\n'* ]] || return 1
        found=true
    done
    [[ $found == true ]]
}

listeners_owned() {
    local listeners=$1 bindings=$2 listener
    while IFS= read -r listener; do
        [[ -z $listener ]] || owned_proxy_listener "$listener" "$bindings" || return 1
    done <<< "$listeners"
}

port_available() {
    local port=$1 containers container labels bindings host bound protocol address addresses proxy_bindings=
    containers=$(docker ps -q) || fail "Cannot inspect running containers"
    for container in $containers; do
        bindings=$(docker inspect --format '{{range $port, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{printf "%s|%s|%s\n" .HostIp .HostPort $port}}{{end}}{{end}}' "$container") ||
            fail "Cannot inspect port bindings of $container"
        labels=$(container_identity "$container")
        while IFS='|' read -r host bound protocol; do
            [[ $bound == "$port" && $protocol == */tcp ]] || continue
            owned_container "$labels" || return 1
            addresses=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{printf "%s\n%s\n" .IPAddress .GlobalIPv6Address}}{{end}}' "$container") ||
                fail "Cannot inspect addresses of owned container"
            while IFS= read -r address; do
                [[ -z $address ]] || proxy_bindings+="$host|$bound|$address|${protocol%/tcp}"$'\n'
            done <<< "$addresses"
        done <<< "$bindings"
    done
    local listeners4 listeners6
    listeners4=$(ss -H -ltnp4 "sport = :$port") || fail "Cannot inspect IPv4 TCP listeners"
    listeners6=$(ss -H -ltnp6 "sport = :$port") || fail "Cannot inspect IPv6 TCP listeners"
    listeners_owned "$listeners4" "$proxy_bindings" || return 1
    listeners_owned "$listeners6" "$proxy_bindings"
}

select_port() {
    local requested=$1 strict=$2 candidate last existing
    [[ $requested =~ ^[0-9]+$ ]] && (( requested >= 1 && requested <= 65535 )) || fail "Invalid port"
    if [[ $OWN_DEPLOYMENT == true && -f $DEPLOY/deploy.env ]]; then
        existing=$(sed -n 's/^SAS_HTTPS_PORT=\([0-9]*\)$/\1/p' "$DEPLOY/deploy.env")
        [[ $existing =~ ^[0-9]+$ ]] && (( existing >= 1 && existing <= 65535 )) || fail "Invalid existing deployment port"
        [[ $strict != true || $requested == "$existing" ]] || fail "Existing port is $existing; do not silently reconfigure it"
        port_available "$existing" || fail "Existing deployment port now overlaps another listener/container; do not displace it"
        SELECTED_PORT=$existing
        return
    fi
    last=$((requested + 99))
    (( last <= 65535 )) || last=65535
    for ((candidate=requested; candidate<=last; candidate++)); do
        if port_available "$candidate"; then SELECTED_PORT=$candidate; return; fi
        [[ $strict != true ]] || fail "Requested port $requested is occupied; no other service will be stopped"
    done
    fail "No free TCP port in $requested-$last; choose another preferred port"
}

if [[ ${1:-} == --preflight ]]; then
    [[ $# == 4 || $# == 6 ]] || fail "Preflight expects directory, port, explicit-port flag and optional profile/explicit-profile"
    DEPLOY=$2
    PROFILE=${5:-registration-cpi-only} PROFILE_EXPLICIT=${6:-false}
    check_profile
    check_host
    printf 'Read-only server OS/architecture: %s\n' "$(uname -a)"
    [[ ! -r /etc/os-release ]] || cat /etc/os-release
    docker info --format 'Docker server: {{.OSType}}/{{.Architecture}}'
    docker ps -a --format 'table {{.Names}}\t{{.Label "com.docker.compose.project"}}\t{{.Ports}}'
    printf 'IPv4 TCP listeners:\n'; ss -H -ltn4
    printf 'IPv6 TCP listeners:\n'; ss -H -ltn6
    if [[ -e $DEPLOY || -L $DEPLOY ]]; then ls -ld "$DEPLOY"; ls -la "$DEPLOY"; fi
    check_directory
    select_port "$3" "$4"
    printf 'SELECTED_HTTPS_PORT=%s\n' "$SELECTED_PORT"
    exit 0
fi

[[ $# == 8 || $# == 9 || $# == 10 || $# == 12 ]] || fail "Expected deployment arguments and optional explicit state/control settings"
UPLOAD=$1 DEPLOY=$2 SERVER_IP=$3 PORT=$4 MUTUAL_TLS=$5 ARCHIVE_SHA=$6 CPI_ALG=$7 CLIENT_ROOT=$8
PROFILE=${9:-registration-cpi-only}
PROFILE_EXPLICIT=false
if (( $# >= 9 )); then PROFILE_EXPLICIT=${10:-true}; fi
STATE_VERSION=${11:-1} OPERATOR_CONTROL=${12:-false}
check_profile
[[ $STATE_VERSION == 1 || $STATE_VERSION == 2 ]] || fail "Invalid state version"
[[ $STATE_VERSION != 2 || $PROFILE == lab-positive ]] || fail "Version2 storage requires positive sessions"
[[ $OPERATOR_CONTROL == true || $OPERATOR_CONTROL == false ]] || fail "Invalid operator-control flag"
[[ $OPERATOR_CONTROL != true || ( $PROFILE == lab-positive && $STATE_VERSION == 2 ) ]] ||
    fail "Operator controls require explicit positive version2"
[[ $PROFILE != lab-positive || $MUTUAL_TLS == true ]] || fail "lab-positive requires mTLS"
[[ $UPLOAD =~ ^/tmp/winnf-mock-sas-upload\.[a-zA-Z0-9]+$ ]] || fail "Unsafe upload path"
[[ $DEPLOY =~ ^/(opt|srv)/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$ ]] || fail "Unsafe deployment path"
[[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || fail "Invalid port"
[[ $SERVER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Expected server IPv4 address"
[[ $MUTUAL_TLS == true || $MUTUAL_TLS == false ]] || fail "Invalid mTLS mode"
[[ $ARCHIVE_SHA =~ ^[a-f0-9]{64}$ ]] || fail "Invalid archive checksum"
[[ $CLIENT_ROOT =~ ^[a-f0-9]{64}$ ]] || fail "Invalid client root fingerprint"
[[ $CPI_ALG == RS256 || $CPI_ALG == ES256 ]] || fail "Invalid CPI algorithm"
check_host
check_directory
select_port "$PORT" true
[[ ! -L $DEPLOY && ! -L $UPLOAD ]] || fail "Deployment/upload directory must not be a symlink"
[[ ! -L $DEPLOY/releases && ! -L $DEPLOY/deploy.env && ! -L $DEPLOY/deploy-settings.json ]] || fail "Deployment metadata paths must not be symlinks"
if [[ -e $DEPLOY/current || -L $DEPLOY/current ]]; then
    [[ -L $DEPLOY/current && $(readlink "$DEPLOY/current") =~ ^$DEPLOY/releases/[a-f0-9]{64}$ ]] || fail "Unexpected existing current path; preserve it and resolve manually"
fi
[[ -f $UPLOAD/package.tar ]] || fail "Uploaded package not found"
[[ $(sha256sum "$UPLOAD/package.tar" | cut -d ' ' -f1) == "$ARCHIVE_SHA" ]] || fail "Package checksum mismatch"
mkdir -p "$DEPLOY"
exec 9>"$DEPLOY/.deploy.lock"
flock -n 9 || fail "Another deployment is running"
if [[ ! -e $DEPLOY/.deployment-owner ]]; then printf '%s\n' "$PROJECT_ID" > "$DEPLOY/.deployment-owner"; fi
mkdir -p "$DEPLOY/releases"
NEW_CREDENTIALS=
cleanup() {
    if [[ -n $NEW_CREDENTIALS && $NEW_CREDENTIALS == "$DEPLOY"/.new-credentials-* ]]; then
        rm -rf -- "$NEW_CREDENTIALS"
    fi
    rm -rf -- "$UPLOAD"
}
trap cleanup EXIT
mkdir "$UPLOAD/source"
while IFS= read -r member; do
    [[ $member != /* && $member != *".."* ]] || fail "Unsafe archive member"
done < <(tar -tf "$UPLOAD/package.tar")
tar -xf "$UPLOAD/package.tar" -C "$UPLOAD/source"
(cd "$UPLOAD/source" && sha256sum -c package.sha256 >/dev/null) || fail "Source manifest verification failed"
RELEASE_ID=$(sha256sum "$UPLOAD/source/package.sha256" | cut -d ' ' -f1)
RELEASE="$DEPLOY/releases/$RELEASE_ID"
[[ ! -L $RELEASE ]] || fail "Release path must not be a symlink"
if [[ -d $RELEASE ]]; then
    (cd "$RELEASE" && sha256sum -c package.sha256 >/dev/null) || fail "Existing release was modified; refusing to overwrite it"
else
    mv "$UPLOAD/source" "$RELEASE"
fi
IMAGE="winnf-mock-sas-lab:${RELEASE_ID:0:24}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f "$RELEASE/Dockerfile.mock-sas" -t "$IMAGE" "$RELEASE"
fi
printf 'Native server architecture: %s\n' "$(uname -m)"
CREDENTIALS="$DEPLOY/mock-sas-lab"
[[ ! -L $CREDENTIALS ]] || fail "Credentials path must not be a symlink, even if dangling"
FRESH=()
CREDENTIAL_MOUNT_OPTIONS=,readonly
if [[ ! -e $CREDENTIALS ]]; then
    NEW_CREDENTIALS=$(mktemp -d "$DEPLOY/.new-credentials-XXXXXXXX")
    docker run --rm --user 0:0 --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges:true --tmpfs /tmp \
        --mount "type=bind,src=$NEW_CREDENTIALS,dst=/lab" \
        "$IMAGE" python generate_lab.py --out /lab --ip "$SERVER_IP" --cpi-alg "$CPI_ALG"
    CHECK_CREDENTIALS=$NEW_CREDENTIALS
    FRESH=(--fresh)
    CREDENTIAL_MOUNT_OPTIONS=
else
    [[ -d $CREDENTIALS && ! -L $CREDENTIALS ]] || fail "Existing credentials path is unsafe"
    CHECK_CREDENTIALS=$CREDENTIALS
fi
PREPARE_ARGS=(--state-version "$STATE_VERSION" --operator-control "$OPERATOR_CONTROL")
if [[ $PROFILE == lab-positive ]]; then
    [[ -f $RELEASE/inputs/lab-policy.json && ! -L $RELEASE/inputs/lab-policy.json ]] || fail "Explicit LAB policy missing or unsafe"
    PREPARE_ARGS+=(--profile lab-positive --lab-policy /source/inputs/lab-policy.json)
    PREPARE_ARGS+=(--state-directory /deployment/lab-state)
fi
if [[ $MUTUAL_TLS == true ]]; then
    [[ -f $RELEASE/inputs/client-ca.pem ]] || fail "Real radio client CA required; no automatic no-client-cert fallback"
    PREPARE_ARGS+=(--client-ca /source/inputs/client-ca.pem --expected-root "$CLIENT_ROOT")
fi
if [[ -f $RELEASE/inputs/radio-trust-bundle.pem ]]; then
    PREPARE_ARGS+=(--radio-trust-bundle /source/inputs/radio-trust-bundle.pem)
fi
[[ ! -L $RELEASE/exports ]] || fail "Exports directory must not be a symlink"
mkdir -p "$RELEASE/exports"
docker run --rm --user 0:0 --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges:true --tmpfs /tmp \
    --mount "type=bind,src=$CHECK_CREDENTIALS,dst=/lab$CREDENTIAL_MOUNT_OPTIONS" \
    --mount "type=bind,src=$DEPLOY,dst=/deployment" \
    --mount "type=bind,src=$RELEASE,dst=/source" \
    "$IMAGE" python deploy_support.py prepare --credentials /lab \
    --settings /deployment/deploy-settings.json --output /source/exports \
    --server-ip "$SERVER_IP" --port "$PORT" --mutual-tls "$MUTUAL_TLS" \
    --check-permissions "${FRESH[@]}" "${PREPARE_ARGS[@]}"
if [[ -n $NEW_CREDENTIALS ]]; then
    chown -R 10001:10001 "$NEW_CREDENTIALS/runtime" "$NEW_CREDENTIALS/config"
    chmod 700 "$NEW_CREDENTIALS/runtime" "$NEW_CREDENTIALS/config" "$NEW_CREDENTIALS/signer"
    chmod 600 "$NEW_CREDENTIALS/runtime/server-key.pem" "$NEW_CREDENTIALS"/signer/*-key.pem
    mv "$NEW_CREDENTIALS" "$CREDENTIALS"
    NEW_CREDENTIALS=
fi
ENV_FILE="$DEPLOY/deploy.env"
EXPECTED_ENV=$(printf 'SAS_RUN_UID=10001\nSAS_RUN_GID=10001\nSAS_HTTPS_PORT=%s\nSAS_BIND_ADDRESS=0.0.0.0\nSAS_REQUIRE_CLIENT_CERT=%s\n' "$PORT" "$MUTUAL_TLS")
if [[ -e $ENV_FILE ]]; then
    [[ $(cat "$ENV_FILE") == "$EXPECTED_ENV" ]] || fail "Existing deploy.env differs; refusing automatic reconfiguration"
else
    printf '%s\n' "$EXPECTED_ENV" > "$ENV_FILE"
fi
if [[ -e $RELEASE/mock-sas-lab || -L $RELEASE/mock-sas-lab ]]; then
    [[ -L $RELEASE/mock-sas-lab && $(readlink "$RELEASE/mock-sas-lab") == "$CREDENTIALS" ]] || fail "Unexpected credentials link in release"
else
    ln -s "$CREDENTIALS" "$RELEASE/mock-sas-lab"
fi
export SAS_IMAGE=$IMAGE SAS_RUN_UID=10001 SAS_RUN_GID=10001 SAS_HTTPS_PORT=$PORT
export SAS_BIND_ADDRESS=0.0.0.0 SAS_REQUIRE_CLIENT_CERT=$MUTUAL_TLS
export SAS_DEPLOYMENT_ID=$PROJECT_ID
export SAS_STATE_VERSION=$STATE_VERSION SAS_OPERATOR_CONTROL_ENABLED=$OPERATOR_CONTROL
COMPOSE=(docker compose --env-file "$ENV_FILE" --project-name "$PROJECT" -f "$RELEASE/compose.mock-sas.yml")
"${COMPOSE[@]}" config --quiet
if [[ $PROFILE == lab-positive ]]; then
    chown 10001:10001 "$RELEASE/inputs/lab-policy.json"
    chmod 600 "$RELEASE/inputs/lab-policy.json"
    COMPOSE+=(-f "$RELEASE/compose.mock-sas.lab-positive.yml")
    STATE="$DEPLOY/lab-state"
    if [[ ! -e $STATE ]]; then
        mkdir -m 700 "$STATE"
        chown 10001:10001 "$STATE"
    fi
    if [[ -e $RELEASE/lab-state || -L $RELEASE/lab-state ]]; then
        [[ -L $RELEASE/lab-state && $(readlink "$RELEASE/lab-state") == "$STATE" ]] ||
            fail "Unexpected persistent state link in release"
    else
        ln -s "$STATE" "$RELEASE/lab-state"
    fi
    "${COMPOSE[@]}" config --quiet
fi
"${COMPOSE[@]}" config --quiet
check_directory
port_available "$PORT" || fail "Port became occupied during build; aborting without stopping other services"
"${COMPOSE[@]}" up -d --no-build --no-deps mock-sas
docker run --rm --user 0:0 --network host --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --tmpfs /tmp \
    --mount "type=bind,src=$RELEASE/exports/radio-server-ca.pem,dst=/server-ca.pem,readonly" \
    "$IMAGE" python deploy_support.py probe --ca /server-ca.pem \
    --server-ip "$SERVER_IP" --port "$PORT" --mutual-tls "$MUTUAL_TLS"
CONTAINER=$("${COMPOSE[@]}" ps -q mock-sas)
[[ -n $CONTAINER ]] || fail "Owned service container missing"
[[ $(container_identity "$CONTAINER") == "$PROJECT|$PROJECT_ID|$PROFILE" ]] || fail "Active container profile/ownership mismatch"
PROFILE_DIGEST=none
if [[ $PROFILE == lab-positive ]]; then PROFILE_DIGEST=$(sha256sum "$RELEASE/inputs/lab-policy.json" | cut -d ' ' -f1); fi
STARTED=$(docker inspect --format '{{.State.StartedAt}}' "$CONTAINER")
READY=false
for ((attempt=0; attempt<60; attempt++)); do
    if [[ $(docker inspect --format '{{.State.Running}}' "$CONTAINER") == true ]] &&
       docker logs --since "$STARTED" "$CONTAINER" 2>&1 |
           grep -F "LAB profile active: $PROFILE; policy SHA256: $PROFILE_DIGEST" >/dev/null; then
        READY=true
        break
    fi
    sleep 1
done
[[ $READY == true ]] || fail "Worker profile/policy startup marker not verified; no radio success claimed"
docker logs --since "$STARTED" "$CONTAINER" 2>&1 |
    grep -F "LAB settings active: stateVersion=$STATE_VERSION; operatorControlEnabled=$OPERATOR_CONTROL" >/dev/null ||
    fail "Worker state/control settings not verified"
if [[ $OPERATOR_CONTROL == true ]]; then
    docker logs --since "$STARTED" "$CONTAINER" 2>&1 |
        grep -F 'LAB operator control ready: private Unix socket; explicit commands only' >/dev/null ||
        fail "Private operator control worker not verified"
fi
if [[ $PROFILE == lab-positive ]]; then
    docker logs --since "$STARTED" "$CONTAINER" 2>&1 |
        grep -F 'LAB state persistence active: atomic-json' >/dev/null ||
        fail "Durable state worker startup marker not verified"
    [[ -f $STATE/session.json && ! -L $STATE/session.json ]] || fail "Durable state snapshot missing"
    [[ $(stat -c %u:%g:%a "$STATE/session.json") == 10001:10001:600 ]] ||
        fail "Durable state snapshot ownership/mode invalid"
    [[ $(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/state"}}{{.RW}}{{end}}{{end}}' "$CONTAINER") == true ]] ||
        fail "Dedicated state writable mount missing"
fi
printf '%s\n' "$PROFILE" > "$DEPLOY/.active-profile"
chmod 600 "$DEPLOY/.active-profile"
if [[ ! -L $DEPLOY/current || $(readlink "$DEPLOY/current") != "$RELEASE" ]]; then
    ln -s "$RELEASE" "$DEPLOY/.current-next"
    mv -Tf "$DEPLOY/.current-next" "$DEPLOY/current"
fi
printf 'Deployment prepared at %s; radio endpoint https://%s:%s/v1.2/\n' "$DEPLOY" "$SERVER_IP" "$PORT"
printf 'Radio end-to-end registration is NOT verified. No firewall rules were modified.\n'
printf 'COMPOSE_PROJECT=%s\n' "$PROJECT"
printf 'ACTIVE_PROFILE=%s\n' "$PROFILE"
printf 'EXPORT_DIRECTORY=%s/exports\n' "$RELEASE"
