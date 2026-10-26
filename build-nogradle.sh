#!/usr/bin/env bash
#
# Fallback build without Gradle. Downloads the two compile dependencies from
# Maven Central, compiles all sources with javac, and assembles a loadable
# Burp extension JAR (Gson bundled, Montoya excluded). Requires JDK 17+.
#
# Usage:  ./build-nogradle.sh
# Output: build/sqlihunter-1.0.0.jar
#
set -euo pipefail

MONTOYA_VERSION="2025.12"
GSON_VERSION="2.11.0"
LIB_DIR="build/libs-cache"
OUT_JAR="build/sqlihunter-1.0.0.jar"

mkdir -p "$LIB_DIR" build/classes build/jar

fetch() { # url dest
  if [ ! -f "$2" ]; then
    echo "Downloading $(basename "$2")"
    curl -fsSL -o "$2" "$1"
  fi
}

MONTOYA_JAR="$LIB_DIR/montoya-api-$MONTOYA_VERSION.jar"
GSON_JAR="$LIB_DIR/gson-$GSON_VERSION.jar"
fetch "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/$MONTOYA_VERSION/montoya-api-$MONTOYA_VERSION.jar" "$MONTOYA_JAR"
fetch "https://repo1.maven.org/maven2/com/google/code/gson/gson/$GSON_VERSION/gson-$GSON_VERSION.jar" "$GSON_JAR"

echo "Compiling sources..."
find src/main/java -name '*.java' > build/sources.txt
javac -d build/classes -cp "$MONTOYA_JAR:$GSON_JAR" @build/sources.txt

echo "Assembling JAR (Gson bundled, Montoya excluded)..."
rm -rf build/jar && mkdir -p build/jar
cp -r build/classes/* build/jar/
( cd build/jar && unzip -oq "../../$GSON_JAR" 'com/*' && rm -rf META-INF )
jar cf "$OUT_JAR" -C build/jar .

echo "Built: $OUT_JAR"
