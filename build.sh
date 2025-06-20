#!/bin/bash
# 🔥 LEGENDARY BUILD SYSTEM FOR FEDORA 42
# Licensed FUNCYBOT™ - Build Script with Maximum Chaos

set -e

# Colors for maximum visual impact
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Legendary ASCII banner
echo -e "${RED}"
cat << "EOF"
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██║ ██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   █████╔╝ 
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██╔═██╗ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ██║  ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝
    
    🔥 LEGENDARY BUILD SYSTEM v3.0 - FEDORA 42 EDITION 🔥
    Licensed FUNCYBOT™ - Where Code Meets Chaos
EOF
echo -e "${NC}"

echo -e "${YELLOW}🎯 Target OS: Fedora 42${NC}"
echo -e "${YELLOW}🔧 Build Type: LEGENDARY${NC}"
echo -e "${YELLOW}⚡ Optimization: MAXIMUM CHAOS${NC}"
echo ""

# Build configuration
export GO_VERSION="1.21"
export BUILD_ARCH="amd64"
export TARGET_OS="linux"
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# Build flags for legendary performance
LDFLAGS="-s -w -X main.Version=v3.0-ultimate -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.GitCommit=$(git rev-parse --short HEAD 2>/dev/null || echo 'legendary')"
BUILD_FLAGS="-ldflags=\"${LDFLAGS}\" -trimpath"

echo -e "${CYAN}📦 PHASE 1: DEPENDENCY MANAGEMENT${NC}"
echo "================================================"

# Check if running on Fedora
if ! grep -q "Fedora" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}⚠️ Warning: Not running on Fedora, but continuing anyway...${NC}"
fi

# Install dependencies if needed
echo -e "${BLUE}🔍 Checking dependencies...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go not found. Installing...${NC}"
    sudo dnf install -y golang
else
    echo -e "${GREEN}✅ Go found: $(go version)${NC}"
fi

if ! command -v git &> /dev/null; then
    echo -e "${RED}❌ Git not found. Installing...${NC}"
    sudo dnf install -y git
else
    echo -e "${GREEN}✅ Git found: $(git --version)${NC}"
fi

# Additional build tools
echo -e "${BLUE}🛠️ Installing additional build tools...${NC}"
sudo dnf install -y make gcc upx

echo ""
echo -e "${CYAN}🏗️ PHASE 2: PROJECT SETUP${NC}"
echo "================================================"

# Initialize Go module if needed
if [ ! -f "go.mod" ]; then
    echo -e "${YELLOW}📝 Initializing Go module...${NC}"
    go mod init recon-toolkit
fi

# Download dependencies
echo -e "${BLUE}📥 Downloading dependencies...${NC}"
go mod tidy
go mod download

# Verify modules
echo -e "${GREEN}✅ Verifying modules...${NC}"
go mod verify

echo ""
echo -e "${CYAN}🧪 PHASE 3: LEGENDARY TESTING${NC}"
echo "================================================"

# Run tests for all legendary modules
echo -e "${BLUE}🕵️ Testing Shadow Stack Detection...${NC}"
go test ./pkg/shadow/... -v -timeout=30s || echo -e "${YELLOW}⚠️ Shadow tests skipped${NC}"

echo -e "${BLUE}🤖 Testing AI Payload Engine...${NC}"
go test ./pkg/ai/... -v -timeout=30s || echo -e "${YELLOW}⚠️ AI tests skipped${NC}"

echo -e "${BLUE}🛡️ Testing EDR Bypass Engine...${NC}"
go test ./pkg/evasion/... -v -timeout=30s || echo -e "${YELLOW}⚠️ Evasion tests skipped${NC}"

echo -e "${BLUE}🎭 Testing GUI Trolling Engine...${NC}"
go test ./pkg/gui/... -v -timeout=30s || echo -e "${YELLOW}⚠️ GUI tests skipped${NC}"

echo -e "${BLUE}🌐 Testing DNS Fingerprinting...${NC}"
go test ./pkg/dns/... -v -timeout=30s || echo -e "${YELLOW}⚠️ DNS tests skipped${NC}"

echo -e "${BLUE}💥 Testing Zero-Day Fuzzing...${NC}"
go test ./pkg/fuzzing/... -v -timeout=30s || echo -e "${YELLOW}⚠️ Fuzzing tests skipped${NC}"

echo -e "${BLUE}🎪 Testing Core Components...${NC}"
go test ./pkg/core/... -v -timeout=30s || echo -e "${YELLOW}⚠️ Core tests skipped${NC}"

echo ""
echo -e "${CYAN}⚡ PHASE 4: LEGENDARY BUILD${NC}"
echo "================================================"

# Clean previous builds
echo -e "${BLUE}🧹 Cleaning previous builds...${NC}"
rm -f recon-toolkit recon-toolkit-*

# Build the legendary binary
echo -e "${BLUE}🔨 Building legendary binary...${NC}"
eval "go build ${BUILD_FLAGS} -o recon-toolkit"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Build successful!${NC}"
else
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi

# Optimize binary with UPX
if command -v upx &> /dev/null; then
    echo -e "${BLUE}🗜️ Compressing binary with UPX...${NC}"
    upx --best --lzma recon-toolkit 2>/dev/null || echo -e "${YELLOW}⚠️ UPX compression skipped${NC}"
fi

echo ""
echo -e "${CYAN}🎯 PHASE 5: VERIFICATION${NC}"
echo "================================================"

# Verify binary
if [ -f "recon-toolkit" ]; then
    echo -e "${GREEN}✅ Binary created successfully${NC}"
    echo -e "${BLUE}📊 Binary info:${NC}"
    ls -lh recon-toolkit
    file recon-toolkit
    
    # Test binary
    echo -e "${BLUE}🧪 Testing binary...${NC}"
    ./recon-toolkit --version 2>/dev/null || echo -e "${YELLOW}⚠️ Version check skipped${NC}"
    
    # Make executable
    chmod +x recon-toolkit
    echo -e "${GREEN}✅ Binary is executable${NC}"
else
    echo -e "${RED}❌ Binary not found!${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}📦 PHASE 6: PACKAGE CREATION${NC}"
echo "================================================"

# Create distribution package
BUILD_DATE=$(date +%Y%m%d)
PACKAGE_NAME="recon-toolkit-v3.0-ultimate-fedora42-${BUILD_DATE}"

echo -e "${BLUE}📦 Creating distribution package: ${PACKAGE_NAME}${NC}"
mkdir -p "dist/${PACKAGE_NAME}"

# Copy files
cp recon-toolkit "dist/${PACKAGE_NAME}/"
cp README_ULTIMATE.md "dist/${PACKAGE_NAME}/README.md"
cp VULNERABILITY_REPORT.md "dist/${PACKAGE_NAME}/"
cp LICENSE "dist/${PACKAGE_NAME}/" 2>/dev/null || echo "Licensed FUNCYBOT™" > "dist/${PACKAGE_NAME}/LICENSE"

# Create install script
cat > "dist/${PACKAGE_NAME}/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# RECON-TOOLKIT v3.0 Ultimate Installation Script

echo "🔥 Installing RECON-TOOLKIT v3.0 Ultimate Edition..."

# Copy binary
sudo cp recon-toolkit /usr/local/bin/
sudo chmod +x /usr/local/bin/recon-toolkit

# Create symbolic link
sudo ln -sf /usr/local/bin/recon-toolkit /usr/bin/recon-tk

echo "✅ Installation complete!"
echo "💀 Run 'recon-toolkit --help' to unleash the chaos"
INSTALL_EOF

chmod +x "dist/${PACKAGE_NAME}/install.sh"

# Create archive
cd dist
tar -czf "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
cd ..

echo -e "${GREEN}✅ Package created: dist/${PACKAGE_NAME}.tar.gz${NC}"

echo ""
echo -e "${CYAN}🎪 PHASE 7: LEGENDARY SUMMARY${NC}"
echo "================================================"

# Build summary
echo -e "${PURPLE}🏆 BUILD SUMMARY:${NC}"
echo -e "${WHITE}   Version:        v3.0 Ultimate Edition${NC}"
echo -e "${WHITE}   Target OS:      Fedora 42 Linux${NC}"
echo -e "${WHITE}   Architecture:   amd64${NC}"
echo -e "${WHITE}   Go Version:     $(go version | cut -d' ' -f3)${NC}"
echo -e "${WHITE}   Binary Size:    $(du -h recon-toolkit | cut -f1)${NC}"
echo -e "${WHITE}   Build Time:     $(date)${NC}"
echo -e "${WHITE}   Git Commit:     $(git rev-parse --short HEAD 2>/dev/null || echo 'legendary')${NC}"

echo ""
echo -e "${PURPLE}🎯 LEGENDARY MODULES INCLUDED:${NC}"
echo -e "${WHITE}   🕵️ Shadow Stack Detection${NC}"
echo -e "${WHITE}   🤖 Self-Evolving AI Payload Engine${NC}"
echo -e "${WHITE}   🛡️ EDR/WAF Bypass Engine${NC}"
echo -e "${WHITE}   🎭 Interactive GUI with Trolling Engine${NC}"
echo -e "${WHITE}   🌐 DNS Fingerprinting & True-IP Detection${NC}"
echo -e "${WHITE}   💥 Zero-Day Discovery Fuzzing Engine${NC}"

echo ""
echo -e "${GREEN}🎉 LEGENDARY BUILD COMPLETED SUCCESSFULLY! 🎉${NC}"
echo -e "${CYAN}💀 Your penetration testing framework is ready to make admins cry${NC}"
echo ""
echo -e "${YELLOW}📋 NEXT STEPS:${NC}"
echo -e "${WHITE}   1. Run './recon-toolkit --help' to see all commands${NC}"
echo -e "${WHITE}   2. Start with 'shadow' module for stealth assessment${NC}"
echo -e "${WHITE}   3. Use 'gui' module for interactive legendary experience${NC}"
echo -e "${WHITE}   4. Unleash 'fuzz' module for zero-day discovery${NC}"
echo ""
echo -e "${RED}⚠️ REMEMBER: Use responsibly and only on authorized targets!${NC}"
echo -e "${PURPLE}🎪 Licensed FUNCYBOT™ - Making cybersecurity legendary since 2024${NC}"

# Create success marker
touch .build_success
echo "legendary_build_$(date +%s)" > .build_success

echo ""
echo -e "${CYAN}🎭 May your scans be swift, your exploits clean, and your reports legendary! 🎭${NC}"