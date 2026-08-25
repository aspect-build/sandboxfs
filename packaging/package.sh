#!/bin/bash
#
# package.sh — build a shippable, notarized .pkg of the sandboxfs stack:
#   sandbox.app  (host app, the FSKit registration vehicle)
#     └─ Contents/Extensions/fskit-appex.appex   (the FSKit module)
#     └─ Contents/MacOS/sandboxfs               (the Rust CLI, symlinked to PATH
#                                                by postinstall)
#
# The app + appex + CLI ship as ONE version-locked artifact because an FSKit
# module is only discoverable through its containing .app, and the CLI is
# useless without the matching appex.
#
# Pipeline:  archive → assemble → sign (inside-out, Developer ID) →
#            pkgbuild → productbuild (signed) → notarize → staple
#
# ── Modes ───────────────────────────────────────────────────────────────────
#   Real distribution (needs certs + notary creds):
#       ./packaging/package.sh
#   Local dry run (no certs needed — adhoc sign, no installer sign, no notarize;
#   validates the whole assembly + pkg layout + postinstall):
#       SANDBOXFS_ADHOC=1 ./packaging/package.sh
#
# ── Config (env overrides) ───────────────────────────────────────────────────
#   SANDBOXFS_TEAM_ID            Apple Developer team id        (default 2SZJVCZSQ6)
#   SANDBOXFS_DEVID_APP          "Developer ID Application: …"  codesign identity
#   SANDBOXFS_DEVID_INSTALLER    "Developer ID Installer: …"    productbuild identity
#   SANDBOXFS_NOTARY_PROFILE     notarytool keychain profile    (default sandboxfs-notary)
#   SANDBOXFS_PROVISION_PROFILE  path to embedded.provisionprofile carrying the
#                                FSKit capability (embedded in app + appex before
#                                signing). Leave unset until the entitlement
#                                question is resolved.
#   SANDBOXFS_ADHOC=1            dry run (see above)
#   SANDBOXFS_VERSION            override the version (else read from Info.plist);
#                                used in pkg/dmg version + artifact filenames
#
set -euo pipefail

# ── locate repo + config ─────────────────────────────────────────────────────
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

# xcodebuild lives inside a full Xcode, not the CommandLineTools. Honor an explicit
# DEVELOPER_DIR, else pick a full Xcode (beta first) so the build works regardless of
# what `xcode-select` points at.
if [ -z "${DEVELOPER_DIR:-}" ]; then
    for x in /Applications/Xcode-beta.app /Applications/Xcode.app; do
        [ -d "$x" ] && { export DEVELOPER_DIR="$x/Contents/Developer"; break; }
    done
fi

PROJECT="sandbox.xcodeproj"
CONFIG="Release"
OUT="$ROOT/dist"
WORK="$OUT/work"

TEAM_ID="${SANDBOXFS_TEAM_ID:-2SZJVCZSQ6}"
DEVID_APP="${SANDBOXFS_DEVID_APP:-Developer ID Application: ($TEAM_ID)}"
DEVID_INSTALLER="${SANDBOXFS_DEVID_INSTALLER:-Developer ID Installer: ($TEAM_ID)}"
NOTARY_PROFILE="${SANDBOXFS_NOTARY_PROFILE:-sandboxfs-notary}"
PROVISION="${SANDBOXFS_PROVISION_PROFILE:-}"
ADHOC="${SANDBOXFS_ADHOC:-0}"

PKG_ID="build.aspect.sandbox.pkg"

ENT_APP="$HERE/entitlements/sandbox.entitlements"
ENT_CLI="$HERE/entitlements/sandboxfs.entitlements"
ENT_APPEX="$ROOT/fskit-appex/SandboxFS.entitlements"

say()  { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

if [ "$ADHOC" = "1" ]; then
    SIGN_ID="-"
    warn "ADHOC dry run: adhoc code signature, unsigned installer, no notarization."
else
    SIGN_ID="$DEVID_APP"
fi

# ── 1. archive (app + embedded appex) and build the CLI ──────────────────────
build() {
    say "archiving $PROJECT (app + appex)…"
    rm -rf "$WORK" && mkdir -p "$WORK"
    ARCHIVE="$WORK/sandbox.xcarchive"
    # We re-sign everything ourselves below, so build without signing here — it
    # keeps the archive step identity-agnostic and reproducible.
    xcodebuild archive \
        -project "$PROJECT" -scheme sandbox -configuration "$CONFIG" \
        -archivePath "$ARCHIVE" \
        CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
        >"$WORK/build-app.log" 2>&1 || { tail -40 "$WORK/build-app.log"; die "app archive failed"; }

    say "building sandboxfs CLI (universal) via cargo…"
    # Both backends live in private repos, and cargo's built-in ssh cannot authenticate to them.
    # Set here rather than in .cargo/config.toml, which is gitignored for the local dev loop.
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
    # The Rust controller (crates/sandboxd, bin `sandboxfs`). The projection backend is
    # developed in its own repository, and the workspace builds against the in-tree stand-in
    # (crates/backend-cfs) so an ordinary build needs no access to it — a cargo feature could not do
    # that, since the resolver reads every dependency's manifest whether a feature enables it
    # or not. A shipped binary must carry the real one, so swap the dependency over for the
    # duration of the build and put it back however this exits. Restoring from a copy, not
    # from git, so an unrelated local edit is never discarded.
    CFS_MANIFEST="$ROOT/crates/sandboxd/Cargo.toml"
    cp "$CFS_MANIFEST" "$WORK/sandboxd-Cargo.toml.orig"
    cp "$ROOT/Cargo.lock" "$WORK/Cargo.lock.orig"
    restore_cfs_dep() {
        cp "$WORK/sandboxd-Cargo.toml.orig" "$CFS_MANIFEST"
        cp "$WORK/Cargo.lock.orig" "$ROOT/Cargo.lock"
    }
    trap restore_cfs_dep EXIT
    sed -i '' 's|^backend-cfs = { path = "../backend-cfs" }$|backend-cfs = { git = "ssh://git@github.com/aspect-build/cfs.git", branch = "main" }|' "$CFS_MANIFEST"
    grep -q '^backend-cfs = { git = ' "$CFS_MANIFEST" || die "could not point the backend-cfs dependency at its git source"
    # A path override (cargo's `paths`, e.g. from a .cargo/config.toml in a parent directory)
    # outranks the manifest and would quietly build whatever is in a local checkout. Confirm what
    # actually resolved, so a release can only ever carry published code.
    cfs_src="$(cargo tree -p sandboxd -e normal 2>/dev/null | grep -m1 'backend-cfs v')"
    case "$cfs_src" in
        *"aspect-build/cfs.git"*) ;;
        *) die "backend-cfs resolved to '${cfs_src:-nothing}', not its git source — a local path override would ship unpublished code" ;;
    esac

    # cargo can't emit a fat binary directly, so build both slices and lipo them — the
    # app+appex archive is already x86_64+arm64, and a host-arch-only CLI would leave the
    # other arch without a working `sandboxfs`.
    rustup target add x86_64-apple-darwin aarch64-apple-darwin >/dev/null 2>&1 || true
    cargo build --release -p sandboxd --target x86_64-apple-darwin \
        >"$WORK/build-cli.log" 2>&1 || { tail -40 "$WORK/build-cli.log"; die "cli build (x86_64) failed"; }
    cargo build --release -p sandboxd --target aarch64-apple-darwin \
        >>"$WORK/build-cli.log" 2>&1 || { tail -40 "$WORK/build-cli.log"; die "cli build (arm64) failed"; }
    lipo -create -output "$WORK/sandboxfs" \
        "$ROOT/target/x86_64-apple-darwin/release/sandboxfs" \
        "$ROOT/target/aarch64-apple-darwin/release/sandboxfs" \
        || die "lipo failed to build universal sandboxfs"

    APP_SRC="$ARCHIVE/Products/Applications/sandbox.app"
    CLI_SRC="$WORK/sandboxfs"
    [ -d "$APP_SRC" ] || die "no app at $APP_SRC"
    [ -f "$CLI_SRC" ] || die "no cli at $CLI_SRC"
}

# ── 2. assemble: stage the app and embed the CLI inside it ───────────────────
assemble() {
    say "assembling bundle (embedding CLI)…"
    STAGE="$WORK/root"                 # pkgbuild --root; mirrors /Applications
    rm -rf "$STAGE" && mkdir -p "$STAGE"
    APP="$STAGE/sandbox.app"
    cp -R "$APP_SRC" "$APP"
    APPEX="$APP/Contents/Extensions/fskit-appex.appex"
    [ -d "$APPEX" ] || die "appex missing in app: $APPEX"

    # CLI rides inside the app at Contents/MacOS/sandboxfs (version-locked to
    # the appex). postinstall symlinks it to /usr/local/bin/sandboxfs.
    cp "$CLI_SRC" "$APP/Contents/MacOS/sandboxfs"
    chmod 755 "$APP/Contents/MacOS/sandboxfs"

    # Ship the metricsd LaunchDaemon plist inside the app; the postinstall
    # installs it to /Library/LaunchDaemons and bootstraps `sandboxfs metricsd`.
    mkdir -p "$APP/Contents/Resources"
    cp "$HERE/build.aspect.sandbox.metricsd.plist" \
       "$APP/Contents/Resources/build.aspect.sandbox.metricsd.plist"

    # Strip extended attributes (quarantine, provenance, resource forks) BEFORE
    # signing — otherwise pkgbuild emits them as `._*` AppleDouble files into the
    # payload (and warns "write: Permission denied"), which pollutes the install
    # and irritates notarization. Must run pre-sign so we don't strip the seal.
    xattr -cr "$APP"

    VERSION="${SANDBOXFS_VERSION:-$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")}"
    [ -n "$VERSION" ] || die "could not read app version"
    say "version $VERSION"

    # Optional: embed the provisioning profile carrying the FSKit capability into
    # both the app and the appex before signing (Developer ID apps need a profile
    # to carry com.apple.developer.* entitlements).
    if [ -n "$PROVISION" ]; then
        [ -f "$PROVISION" ] || die "provisioning profile not found: $PROVISION"
        say "embedding provisioning profile"
        cp "$PROVISION" "$APP/Contents/embedded.provisionprofile"
        cp "$PROVISION" "$APPEX/Contents/embedded.provisionprofile"
    fi
    # Note: no provisioning profile is needed. The FSKit entitlement
    # (com.apple.developer.fskit.fsmodule) was verified 2026-06-17 to pass Apple
    # notarization under a plain Developer ID signature (submission Accepted,
    # stapled, Gatekeeper "Notarized Developer ID"). SANDBOXFS_PROVISION_PROFILE
    # remains available only as a fallback if Apple's policy ever changes.
}

# ── 3. sign inside-out with the hardened runtime ─────────────────────────────
sign_one() { # <entitlements> <path>
    local ent="$1" path="$2"
    local args=(--force --sign "$SIGN_ID" --options runtime --entitlements "$ent")
    [ "$ADHOC" = "1" ] || args+=(--timestamp)
    codesign "${args[@]}" "$path"
}

sign() {
    say "signing (inside-out) with: $SIGN_ID"
    # Nested code first, container last — the app's signature seals the
    # already-signed appex + CLI.
    sign_one "$ENT_APPEX" "$APPEX"
    sign_one "$ENT_CLI"   "$APP/Contents/MacOS/sandboxfs"
    sign_one "$ENT_APP"   "$APP"

    say "verifying signature…"
    codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | sed 's/^/    /' || die "codesign verify failed"
    if [ "$ADHOC" = "1" ]; then
        warn "adhoc: skipping spctl Gatekeeper assessment (would fail by design)"
    else
        spctl --assess --type execute --verbose=2 "$APP" 2>&1 | sed 's/^/    /' \
            || warn "spctl assessment not yet passing (expected until notarized)"
    fi
}

# ── 4. build the .pkg (component → distribution) ─────────────────────────────
pkg() {
    say "pkgbuild (component)…"
    mkdir -p "$OUT"
    # Stage scripts in a clean dir with no extended attributes (same AppleDouble
    # hazard as the app payload).
    local scripts_dir="$WORK/scripts"
    rm -rf "$scripts_dir" && mkdir -p "$scripts_dir"
    cp "$HERE/scripts/postinstall" "$scripts_dir/postinstall"
    xattr -c "$scripts_dir/postinstall" 2>/dev/null || true
    chmod 755 "$scripts_dir/postinstall"
    local component="$WORK/sandbox-component.pkg"
    pkgbuild \
        --root "$STAGE" \
        --install-location /Applications \
        --scripts "$scripts_dir" \
        --identifier "$PKG_ID" \
        --version "$VERSION" \
        "$component"

    say "productbuild (distribution)…"
    FINAL="$OUT/sandbox-$VERSION.pkg"
    local prod_args=(
        --distribution "$HERE/distribution.xml"
        --package-path "$WORK"
        --resources "$HERE/resources"
    )
    [ "$ADHOC" = "1" ] || prod_args+=(--sign "$DEVID_INSTALLER" --timestamp)
    # distribution.xml references the component by its basename.
    ( cd "$WORK" && productbuild "${prod_args[@]}" "$FINAL" )
    say "built $FINAL"
}

# ── 5. notarize + staple ─────────────────────────────────────────────────────
notarize() {
    if [ "$ADHOC" = "1" ]; then
        warn "adhoc: skipping notarization."
        return
    fi
    say "submitting to notary service (profile: $NOTARY_PROFILE)…"
    xcrun notarytool submit "$FINAL" --keychain-profile "$NOTARY_PROFILE" --wait \
        || die "notarization failed (see: xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE)"
    say "stapling…"
    xcrun stapler staple "$FINAL"
    xcrun stapler validate "$FINAL"
}

# ── 6. wrap the notarized .pkg in a .dmg (via create-dmg) ─────────────────────
dmg() {
    command -v create-dmg >/dev/null || die "create-dmg not found — install it: brew install create-dmg"
    say "building .dmg (create-dmg)…"
    DMG="$OUT/sandboxfs-$VERSION.dmg"
    local dmgroot="$WORK/dmg"
    rm -rf "$dmgroot" && mkdir -p "$dmgroot"
    cp "$FINAL" "$dmgroot/"
    rm -f "$DMG"
    # create-dmg codesigns + notarizes + staples the .dmg itself when given the
    # identity/profile, so there's nothing to do after it here.
    local args=(--volname "sandboxfs $VERSION")
    if [ "$ADHOC" = "1" ]; then
        warn "adhoc: skipping dmg signing/notarization."
    else
        args+=(--codesign "$DEVID_APP" --notarize "$NOTARY_PROFILE")
    fi
    create-dmg "${args[@]}" "$DMG" "$dmgroot" || die "create-dmg failed"
    say "built $DMG"
}

build
assemble
sign
pkg
notarize
dmg

say "done → $FINAL"
say "done → $DMG"
[ "$ADHOC" = "1" ] && warn "this is an ADHOC build — NOT distributable. Re-run without SANDBOXFS_ADHOC for a real artifact."
exit 0
