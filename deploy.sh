#!/bin/bash
# ZeroClaw VPS Deployment Script
# Supports: MiniMax, Gemini, Cloudflare Zero Trust
#
# Usage:
#   ./deploy.sh                    # Interactive mode
#   ./deploy.sh --minimax KEY     # Deploy with MiniMax
#   ./deploy.sh --gemini KEY      # Deploy with Gemini
#   ./deploy.sh --no-auth         # Disable pairing (for Cloudflare Zero Trust)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Defaults
PROVIDER="minimax"
MODEL="MiniMax-M2.5"
CONTAINER_NAME="zeroclaw"
PORT=42617
AUTH_ENABLED=true

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
ZeroClaw VPS Deployment Script

Usage: $0 [OPTIONS]

Options:
    --minimax KEY       Deploy with MiniMax API key
    --gemini KEY        Deploy with Gemini API key
    --provider NAME     Provider name (minimax, gemini, openai, anthropic)
    --model MODEL       Model name
    --port PORT         Port (default: 42617)
    --no-auth           Disable pairing (use with Cloudflare Zero Trust)
    --cloudflare TOKEN  Enable Cloudflare Tunnel with token
    -h, --help          Show this help

Examples:
    $0 --minimax sk-xxx
    $0 --gemini xxx --no-auth
    $0 --cloudflare xxx

Environment Variables:
    MINIMAX_API_KEY     MiniMax API key
    GEMINI_API_KEY      Gemini API key
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimax)
            PROVIDER="minimax"
            MODEL="MiniMax-M2.5"
            API_KEY="$2"
            shift 2
            ;;
        --gemini)
            PROVIDER="gemini"
            MODEL="gemini-2.0-flash"
            API_KEY="$2"
            shift 2
            ;;
        --provider)
            PROVIDER="$2"
            shift 2
            ;;
        --model)
            MODEL="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --no-auth)
            AUTH_ENABLED=false
            shift
            ;;
        --cloudflare)
            CLOUDFLARE_TOKEN="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Check for API key
if [ -z "$API_KEY" ]; then
    if [ -n "$MINIMAX_API_KEY" ]; then
        PROVIDER="minimax"
        MODEL="MiniMax-M2.5"
        API_KEY="$MINIMAX_API_KEY"
    elif [ -n "$GEMINI_API_KEY" ]; then
        PROVIDER="gemini"
        MODEL="gemini-2.0-flash"
        API_KEY="$GEMINI_API_KEY"
    else
        log_error "No API key provided. Use --minimax or --gemini"
        exit 1
    fi
fi

log_info "Deploying ZeroClaw with:"
log_info "  Provider: $PROVIDER"
log_info "  Model: $MODEL"
log_info "  Port: $PORT"
log_info "  Auth: $([ "$AUTH_ENABLED" = true ] && echo "Enabled (Pairing)" || echo "Disabled")"

# Stop existing container
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    log_warn "Removing existing container..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# Create necessary directories
mkdir -p ~/.zeroclaw

# Generate config
cat > ~/.zeroclaw/config.toml << EOF
workspace_dir = "/zeroclaw-data/workspace"
api_key = "$API_KEY"
default_provider = "$PROVIDER"
default_model = "$MODEL"

[gateway]
port = 42617
host = "[::]"
allow_public_bind = true
require_pairing = $AUTH_ENABLED
pair_rate_limit_per_minute = 10

[limits]
max_concurrent_tools = 10
tool_timeout_secs = 120

[memory]
backend = "markdown"
EOF

# Add Cloudflare tunnel if provided
if [ -n "$CLOUDFLARE_TOKEN" ]; then
    cat >> ~/.zeroclaw/config.toml << EOF

[tunnel]
provider = "cloudflare"

[cloudflare]
token = "$CLOUDFLARE_TOKEN"
EOF
    log_info "Cloudflare Tunnel enabled"
fi

log_info "Configuration created at ~/.zeroclaw/config.toml"

# Build docker run command
DOCKER_CMD="docker run -d \
    --name $CONTAINER_NAME \
    -p 127.0.0.1:$PORT:42617 \
    -v ~/.zeroclaw:/zeroclaw-data/.zeroclaw \
    -v zeroclaw-data:/zeroclaw-data \
    -e API_KEY=$API_KEY \
    -e PROVIDER=$PROVIDER \
    -e MODEL=$MODEL \
    -e ZEROCLAW_ALLOW_PUBLIC_BIND=true \
    --restart unless-stopped \
    ghcr.io/nishantgoswami-mahakalp/zeroclaw:latest"

# Run container
log_info "Starting ZeroClaw container..."
eval $DOCKER_CMD

# Wait for startup
sleep 3

# Fix config permissions (container runs as root, so we need to fix after)
chmod 600 ~/.zeroclaw/config.toml 2>/dev/null || true

# Check if running
if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    log_info "ZeroClaw is running!"
    
    if [ "$AUTH_ENABLED" = true ]; then
        echo ""
        log_info "PAIRING CODE:"
        docker logs "$CONTAINER_NAME" 2>&1 | grep -i "pairing" | head -5 || echo "Check logs: docker logs $CONTAINER_NAME"
        echo ""
    fi
    
    log_info "Access URLs:"
    echo "  - Local: http://localhost:$PORT"
    if [ -n "$CLOUDFLARE_TOKEN" ]; then
        echo "  - Public: Check container logs for tunnel URL"
    fi
    echo ""
    log_info "Next steps:"
    echo "  - Open http://localhost:$PORT in browser"
    if [ "$AUTH_ENABLED" = true ]; then
        echo "  - Enter pairing code from terminal"
    else
        echo "  - No auth required (Cloudflare Zero Trust protection recommended)"
    fi
else
    log_error "Container failed to start. Check logs:"
    docker logs "$CONTAINER_NAME"
    exit 1
fi
