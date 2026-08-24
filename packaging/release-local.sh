#!/bin/bash
# release-local.sh — cut a GitHub release from this Mac.
#
# The .app/appex needs the macOS 27 beta SDK (Xcode 27) that GitHub-hosted CI
# runners don't have yet, so releases are built here for now (see
# .github/workflows/release.yml). This builds the signed + notarized .dmg and
# .pkg via package.sh, then publishes them with gh.
#
#   ./packaging/release-local.sh            # (re)cut the v0.0.0 prerelease from HEAD
#   ./packaging/release-local.sh v0.1.0     # versioned release (creates the tag)
#
# Needs: Xcode-beta (27), the Developer ID identities in your keychain, the
# `sandboxfs-notary` notarytool profile, and `gh` authenticated.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

REPO="aspect-build/sandboxfs"
: "${SANDBOXFS_DEVID_APP:=Developer ID Application: SAHIN YORT (2SZJVCZSQ6)}"
: "${SANDBOXFS_DEVID_INSTALLER:=Developer ID Installer: SAHIN YORT (2SZJVCZSQ6)}"
: "${SANDBOXFS_NOTARY_PROFILE:=sandboxfs-notary}"
: "${SANDBOXFS_TEAM_ID:=2SZJVCZSQ6}"
export SANDBOXFS_DEVID_APP SANDBOXFS_DEVID_INSTALLER SANDBOXFS_NOTARY_PROFILE SANDBOXFS_TEAM_ID

TAG="${1:-}"
if [ -n "$TAG" ]; then
    case "$TAG" in
        v*.*.*) ;;
        *) echo "usage: $0 [vX.Y.Z]   (omit for a rolling prerelease)" >&2; exit 1 ;;
    esac
    VERSION="${TAG#v}"
    CHANNEL=tag
else
    VERSION="0.0.0"
    CHANNEL=rolling
fi

SANDBOXFS_VERSION="$VERSION" ./packaging/package.sh

STAGE="$(mktemp -d)"
cp "$ROOT/dist/sandboxfs-$VERSION.dmg" "$STAGE/sandboxfs-$VERSION-arm64.dmg"
cp "$ROOT/dist/sandbox-$VERSION.pkg"   "$STAGE/sandboxfs-$VERSION-arm64.pkg"
( cd "$STAGE" && shasum -a 256 * > SHA256SUMS.txt )

if [ "$CHANNEL" = tag ]; then
    gh release create "$TAG" "$STAGE"/* --repo "$REPO" --title "$TAG" \
        --notes-file "$HERE/release-notes.md"
else
    # Re-cut the moving v0.0.0 prerelease at HEAD.
    gh release delete v0.0.0 --repo "$REPO" --cleanup-tag --yes || true
    gh release create v0.0.0 "$STAGE"/* --repo "$REPO" --prerelease \
        --target "$(git rev-parse HEAD)" \
        --title "sandboxfs-0.0.0" \
        --notes-file "$HERE/release-notes.md"
fi
rm -rf "$STAGE"
echo "released $CHANNEL ($VERSION)"
