

set -e

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" ]]; then
    echo "Building on Windows..."
else
    echo "Warning: This is a Windows-specific project. Building on non-Windows platform for development only."
fi

FEATURES=""
RELEASE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            RELEASE=true
            shift
            ;;
        --gpu)
            FEATURES="${FEATURES}gpu-packing,"
            shift
            ;;
        --runpe)
            FEATURES="${FEATURES}runpe,"
            shift
            ;;
        --encryption)
            FEATURES="${FEATURES}encryption,"
            shift
            ;;
        --all)
            FEATURES="gpu-packing,runpe,encryption"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--release] [--gpu] [--runpe] [--encryption] [--all]"
            exit 1
            ;;
    esac
done

FEATURES=$(echo $FEATURES | sed 's/,$//')

BUILD_CMD="cargo build"

if [ "$RELEASE" = true ]; then
    BUILD_CMD="${BUILD_CMD} --release"
    echo "Building in release mode..."
else
    echo "Building in debug mode..."
fi

if [ ! -z "$FEATURES" ]; then
    BUILD_CMD="${BUILD_CMD} --features \"${FEATURES}\""
    echo "Enabled features: ${FEATURES}"
fi

echo "Running: ${BUILD_CMD}"
eval ${BUILD_CMD}

if [ "$RELEASE" = true ]; then
    echo "Build completed successfully! Executable is at: target/release/reflective_loader"
else
    echo "Build completed successfully! Executable is at: target/debug/reflective_loader"
fi

echo "Run with: cargo run -- --help"
