#!/bin/bash
# Repository cleanup script for Gatewarden public release
# Removes internal development artifacts from git history

set -e

echo "=== Gatewarden Repository Cleanup ==="
echo ""
echo "This script will:"
echo "  1. Remove Kiro IDE artifacts from history"
echo "  2. Remove GitHub Copilot instructions from history"
echo "  3. Remove Chat Chronicle skill files from history"
echo "  4. Remove resume_session.prompt.md from history"
echo "  5. Rewrite git history to eliminate these files permanently"
echo ""
echo "⚠️  WARNING: This will rewrite git history!"
echo "⚠️  All remote branches will need force-push after this."
echo "⚠️  Make sure you have a backup before proceeding."
echo ""
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

# Check if git-filter-repo is installed
if ! command -v git-filter-repo &> /dev/null; then
    echo ""
    echo "ERROR: git-filter-repo is not installed."
    echo ""
    echo "Install on Windows/WSL:"
    echo "  py -m pip install git-filter-repo"
    echo "  OR"
    echo "  python3 -m pip install git-filter-repo"
    echo ""
    echo "Install on macOS:"
    echo "  brew install git-filter-repo"
    echo ""
    exit 1
fi

echo ""
echo "=== Creating backup ==="
cd ..
if [ -d "gatewarden-backup" ]; then
    echo "Removing old backup..."
    rm -rf gatewarden-backup
fi
cp -r gatewarden gatewarden-backup
echo "✓ Backup created at ../gatewarden-backup"

cd gatewarden

echo ""
echo "=== Removing files from history ==="

# Remove all Kiro-specific files
git filter-repo --path .kiro --invert-paths --force
git filter-repo --path resume_session.prompt.md --invert-paths --force

# Remove GitHub Copilot instructions
git filter-repo --path .github/copilot-instructions.md --invert-paths --force

# Remove Chat Chronicle skill
git filter-repo --path .github/skills/chat-chronicle --invert-paths --force

echo ""
echo "=== Cleanup Summary ==="
echo "✓ Removed .kiro/ directory from all commits"
echo "✓ Removed resume_session.prompt.md from all commits"
echo "✓ Removed .github/copilot-instructions.md from all commits"
echo "✓ Removed .github/skills/chat-chronicle/ from all commits"

echo ""
echo "=== Repository Statistics ==="
echo "Commits before cleanup: 30 (original)"
NEW_COUNT=$(git log --all --oneline | wc -l)
echo "Commits after cleanup: $NEW_COUNT"

echo ""
echo "=== Next Steps ==="
echo "1. Review the changes:"
echo "   git log --oneline"
echo "   git status"
echo ""
echo "2. If satisfied, force-push to remote:"
echo "   git push origin --force --all"
echo "   git push origin --force --tags"
echo ""
echo "3. If NOT satisfied, restore from backup:"
echo "   cd .."
echo "   rm -rf gatewarden"
echo "   cp -r gatewarden-backup gatewarden"
echo ""
echo "=== Cleanup Complete ==="
