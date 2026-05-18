# ============================================================
# Kernel CVE Livepatch Agent - Environment Setup Script
# ============================================================
# This script sets up the Linux environment for full kpatch-build
# integration testing. Run inside WSL2 or a Linux VM.
#
# Prerequisites:
#   - WSL2 (Ubuntu 20.04+) or a Linux VM
#   - Docker (optional, for containerized builds)
#   - ~5GB disk space for kernel source tree
# ============================================================

set -euo pipefail

# --- Configuration ---
KERNEL_VERSION="${KERNEL_VERSION:-6.6.102-5.2.an23.x86_64}"
KERNEL_BASE="${KERNEL_VERSION%%.*}"
WORK_DIR="${HOME}/kernel-livepatch-env"

echo "=== Kernel Livepatch Agent Environment Setup ==="
echo "Target kernel: ${KERNEL_VERSION}"
echo "Working directory: ${WORK_DIR}"
echo ""

# --- Step 1: Install base dependencies ---
echo "[1/5] Installing base dependencies..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    gcc make git patch diffutils binutils \
    libelf-dev libssl-dev kmod \
    python3 python3-pip python3-venv \
    fakeroot dpkg-dev debhelper \
    bc bison flex libncurses-dev

# --- Step 2: Setup Python virtual environment ---
echo "[2/5] Setting up Python environment..."
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest

# --- Step 3: Install kpatch ---
echo "[3/5] Installing kpatch..."
if ! command -v kpatch-build &>/dev/null; then
    git clone https://github.com/dynup/kpatch.git /tmp/kpatch
    cd /tmp/kpatch
    make
    sudo make install
    cd -
else
    echo "kpatch-build already installed: $(which kpatch-build)"
fi

# --- Step 4: Download kernel source (optional) ---
echo "[4/5] Kernel source setup..."
if [ ! -d "${WORK_DIR}/linux-${KERNEL_BASE}" ]; then
    echo "Kernel source NOT downloaded. You need to manually:"
    echo "  1. Clone the kernel tree matching ${KERNEL_VERSION}"
    echo "  2. Configure it with: make defconfig"
    echo "  3. Build vmlinux: make -j$(nproc) vmlinux"
    echo ""
    echo "For Anolis OS kernels, clone from:"
    echo "  https://gitee.com/anolis/cloud-kernel.git"
    echo ""
    echo "Or use mainline:"
    echo "  git clone --depth=1 --branch v${KERNEL_BASE} \\"
    echo "    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \\"
    echo "    ${WORK_DIR}/linux-${KERNEL_BASE}"
else
    echo "Kernel source already present."
fi

# --- Step 5: Run tests ---
echo "[5/5] Running agent tests..."
cd "$(dirname "$0")"
source venv/bin/activate
python -m pytest tests/ -v

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the agent:"
echo "  source venv/bin/activate"
echo "  python -m agent --cves sample_cves.txt --workdir ./test_run"
echo ""
echo "For full kpatch-build integration, ensure:"
echo "  1. Kernel source tree is configured and built"
echo "  2. vmlinux exists at <kernel-src>/vmlinux"
echo "  3. kpatch-build is in PATH"
