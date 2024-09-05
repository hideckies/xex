#!/usr/bin/env bash

app_name="xex"
version="$1"
zig_out_dir="zig-out"
dist_dir="dist"

# Test before building
echo "[i] Testing $app_name..."
zig build test
if [ $? -ne 0 ]; then
    echo "[x] Failed to test $app_name."
    exit 1
fi

# Remove previous build
echo "[i] Removing previous build..."
rm -rf $zig_out_dir
rm -rf $dist_dir
mkdir -p $dist_dir

# Check if the version is specified
echo "[i] Checking the app version..."
if [ -z "$version" ]; then
    echo "[x] Specify the $app_name version."
    exit 1
fi

# Add new tag to git
echo "[i] Adding the new tag to git..."
git tag $version
if [ $? -ne 0 ]; then
    echo "[x] Failed to create git tag."
    exit 1
fi

# Build & Package
echo "[i] Building xex..."
zig build -Drelease -Dversion="$version"
cd $zig_out_dir
for dir in ./*/; do
    dir=${dir%/}
    dirname=$(basename "$dir")
    tar -cJf "../$dist_dir/$dirname.tar.xz" ./$dirname
done
cd ..


# Push tag to remote repository
echo "[i] Push the tag v$version to remote repository..."
git add . && git commit -m "v$version" && git push origin tag $version
if [ $? -ne 0 ]; then
    echo "[x] Failed to push tag v$version to remote repository."
    exit 1
fi
echo "[+] OK"

# Also push to origin main
echo "[i] Push to remote main branch..."
git push origin main
if [ $? -ne 0 ]; then
    echo "[x] Failed to push to remote repository."
    exit 1
fi
echo "[+] OK"

echo ""
echo "[i] Done"
echo "[i] Don't forget upload the release builds (\"./$dist_dir/*.zip\") to the GitHub release page."
