#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
NRO_FILE="${SCRIPT_DIR}/wg-tester/build/wg_tester.nro"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[*]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[x]${NC} $1"; }

SWITCH_IP="${1:-$SWITCH_IP}"

show_usage() {
    echo "Usage: $0 [SWITCH_IP] [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --rebuild      Force Docker image rebuild"
    echo "  --clean        Clean build artifacts"
    echo "  --shell        Open shell in build container"
    echo "  --lib-only     Only build libwireguard.a"
    echo "  --build-only   Build without deploying"
    echo ""
    echo "Environment:"
    echo "  SWITCH_IP     IP address of Nintendo Switch"
}

FORCE_REBUILD=false
CLEAN=false
OPEN_SHELL=false
LIB_ONLY=false
BUILD_ONLY=false

for arg in "$@"; do
    case $arg in
        --rebuild)
            FORCE_REBUILD=true
            ;;
        --clean)
            CLEAN=true
            ;;
        --shell)
            OPEN_SHELL=true
            ;;
        --lib-only)
            LIB_ONLY=true
            ;;
        --build-only)
            BUILD_ONLY=true
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
    esac
done

DOCKER_IMAGE="switch-wireguard-builder"

if [ "$CLEAN" = true ]; then
    print_status "Cleaning build artifacts..."
    rm -rf "${BUILD_DIR}" "${SCRIPT_DIR}/libwireguard.a" "${SCRIPT_DIR}/wg-tester/build"
    print_status "Clean complete"
    exit 0
fi

IMAGE_EXISTS=$(docker image inspect "$DOCKER_IMAGE" &>/dev/null && echo "yes" || echo "no")

if [ "$FORCE_REBUILD" = "true" ] || [ "$IMAGE_EXISTS" = "no" ]; then
    print_status "Building Docker image..."
    docker build -t "$DOCKER_IMAGE" "${SCRIPT_DIR}"
fi

if [ "$OPEN_SHELL" = true ]; then
    print_status "Opening shell in build container..."
    docker run --rm -it \
        -v "${SCRIPT_DIR}:/build" \
        -w /build \
        "$DOCKER_IMAGE" \
        bash
    exit 0
fi

print_status "Building libwireguard.a..."
docker run --rm \
    -v "${SCRIPT_DIR}:/build" \
    -w /build \
    "$DOCKER_IMAGE" \
    bash -c "make && chmod -R a+rw build/ libwireguard.a"

if [ ! -f "${SCRIPT_DIR}/libwireguard.a" ]; then
    print_error "Library build failed"
    exit 1
fi

print_status "Library build successful: libwireguard.a"

if [ "$LIB_ONLY" = true ]; then
    exit 0
fi

print_status "Building wg-tester..."
docker run --rm \
    -v "${SCRIPT_DIR}:/build" \
    -w /build \
    "$DOCKER_IMAGE" \
    bash -c "
        source /opt/devkitpro/switchvars.sh
        cd wg-tester
        cmake -B build -DPLATFORM_SWITCH=ON -DCMAKE_BUILD_TYPE=Debug
        make -C build wg_tester.nro -j\$(nproc)
        chmod -R a+rw build/
    "

if [ ! -f "$NRO_FILE" ]; then
    print_error "Build failed - NRO not found"
    exit 1
fi

print_status "Build successful: $NRO_FILE"

if [ "$BUILD_ONLY" = true ]; then
    exit 0
fi

if [ -z "$SWITCH_IP" ]; then
    print_warning "No SWITCH_IP provided - skipping deployment"
    echo ""
    echo "To deploy: $0 <SWITCH_IP>"
    echo "   or: SWITCH_IP=192.168.x.x $0"
    exit 0
fi

print_status "Deploying to Switch at ${SWITCH_IP}..."

docker run --rm -it --init \
    --network host \
    -v "${SCRIPT_DIR}:/build" \
    -w /build \
    "$DOCKER_IMAGE" \
    nxlink -s -a "$SWITCH_IP" /build/wg-tester/build/wg_tester.nro

print_status "Done"
