#!/bin/bash
# scripts/check_backlog_resolved.sh
# Automated check for potentially resolved or stale backlog items in code_issues_backlog.md

BACKLOG_FILE="docs/internals/code_issues_backlog.md"

if [ ! -f "$BACKLOG_FILE" ]; then
    echo "❌ Backlog file not found: $BACKLOG_FILE"
    exit 1
fi

echo "🔍 Scanning backlog for potentially stale items..."
echo "--------------------------------------------------"

# Extract open high/critical issues (those starting with 🔴)
# We look for lines starting with ### 🔴 and capture the title and the next few lines for context.
grep -n "^### 🔴" "$BACKLOG_FILE" | while read -r line; do
    line_num=$(echo "$line" | cut -d: -f1)
    title=$(echo "$line" | cut -d: -f2-)

    # Extract the "Target" or "Target Area" if present in the next 5 lines
    target=$(sed -n "$((line_num+1)),$((line_num+5))p" "$BACKLOG_FILE" | grep -iE "\*\*Target( Area)?:\*\*" | head -n1 | sed -E 's/.*\*\*Target( Area)?:\*\* (.*)/\2/')

    if [ -n "$target" ]; then
        # Clean up target string (remove backticks, trim)
        target_clean=$(echo "$target" | sed 's/`//g' | xargs)

        # Check if target refers to a file that exists
        # Handle multiple targets or class names by taking the first word
        first_target=$(echo "$target_clean" | awk '{print $1}' | sed 's/,//g')

        found_file=""
        if [ -f "$first_target" ]; then
            found_file="$first_target"
        else
            # Try to find the file by name if it's a class/partial path
            file_name=$(basename "$first_target" .kt)
            found_file=$(find . -name "${file_name}.kt" -o -name "${file_name}" 2>/dev/null | head -n1)
        fi

        if [ -n "$found_file" ]; then
             # Check git log for recent changes to this file
             # We look for changes in the last 7 days or last 5 commits
             last_change=$(git log -1 --format="%ar" -- "$found_file")
             change_count=$(git rev-list --count HEAD --since="7 days ago" -- "$found_file")

             if [ "$change_count" -gt 0 ]; then
                 echo "⚠️  POTENTIALLY STALE: $title"
                 echo "   - Target: $found_file"
                 echo "   - Recent Changes: $change_count commit(s) in the last 7 days (Last: $last_change)"
                 echo "   - Action: Verify if this issue was addressed in recent commits."
                 echo ""
             fi
        else
             # If target is not a file, search for symbols in the codebase
             symbol=$(echo "$first_target" | sed 's/.*\.//')
             if [ ${#symbol} -gt 3 ]; then
                 matches=$(grep -r -l "$symbol" . --include="*.kt" --exclude-dir=build --exclude-dir=.gradle 2>/dev/null | head -n 5)
                 if [ -n "$matches" ]; then

                    # Check if any of these files changed recently
                    stale=false
                    for f in $matches; do
                        c=$(git rev-list --count HEAD --since="7 days ago" -- "$f")
                        if [ "$c" -gt 0 ]; then
                            stale=true
                            break
                        fi
                    done

                    if [ "$stale" = true ]; then
                        echo "❓ UNCERTAIN: $title"
                        echo "   - Symbol '$symbol' found in modified files."
                        echo "   - Action: Review symbol usage in recent changes."
                        echo ""
                    fi
                 fi
             fi
        fi
    fi
done

echo "--------------------------------------------------"
echo "✅ Scan complete. Please manually verify highlighted items."
