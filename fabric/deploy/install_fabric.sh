#!/bin/bash
# Downloads the Hyperledger Fabric binaries (peer, orderer, configtxgen, cryptogen, osnadmin) into fabric/. No Docker needed.
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"; V="${FABRIC_VERSION:-2.5.10}"
[ -x "$HERE/bin/peer" ] && { echo "Fabric already installed: $("$HERE/bin/peer" version | sed -n 2p)"; exit 0; }
ARCH="$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
URL="https://github.com/hyperledger/fabric/releases/download/v$V/hyperledger-fabric-linux-$ARCH-$V.tar.gz"
echo "downloading $URL"
curl -fL --retry 3 -o /tmp/fabric.tgz "$URL"
tar xzf /tmp/fabric.tgz -C "$HERE" && rm -f /tmp/fabric.tgz
"$HERE/bin/peer" version | sed -n 1,3p
command -v node >/dev/null || echo "Node.js 18+ is also needed (the chaincode and the gateway are Node programs)."
