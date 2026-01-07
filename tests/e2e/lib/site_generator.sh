#!/usr/bin/env bash
set -euo pipefail
# generate simple static site content for testing
E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

generate_site() {
  # generate_site <dir> <version>
  dir=$1
  ver=${2:-1}
  mkdir -p "$dir"
  cat > "$dir/index.html" <<HTML
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Test Site v$ver</title>
    <link rel="stylesheet" href="/style.css">
  </head>
  <body>
    <h1>Test Site</h1>
    <p>Version: $ver</p>
    <script src="/app.js"></script>
  </body>
</html>
HTML

  cat > "$dir/style.css" <<CSS
body { font-family: Arial, sans-serif; background: #f7f7f7; }
h1 { color: #333 }
CSS

  cat > "$dir/app.js" <<JS
console.log('Test site version $ver');
JS

  echo "generated site in $dir (v$ver)"
}
