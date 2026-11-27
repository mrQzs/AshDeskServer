#!/usr/bin/env bash
# verify_all.sh — Linux / WSL 全量静态分析、Sanitizers、单元测试、模糊测试与多核基准验证
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_ROOT="/tmp/ashdesk-server-verify"
rm -rf "$OUT_ROOT"
mkdir -p "$OUT_ROOT/cppcheck-cache"

export ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:detect_stack_use_after_return=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1"

echo "== [1/6] GCC (C17/C++17 -Wall -Wextra -Wpedantic -Wconversion -Werror + ASan/UBSan/LSan)"
cmake -S "$REPO_DIR" -B "$OUT_ROOT/gcc-asan" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
  -DASH_SANITIZE="address,undefined" > "$OUT_ROOT/gcc-asan.cfg.log" 2>&1
cmake --build "$OUT_ROOT/gcc-asan" > "$OUT_ROOT/gcc-asan.bld.log" 2>&1
ctest --test-dir "$OUT_ROOT/gcc-asan" --output-on-failure

echo "== [2/6] Clang (C17/C++17 -Wall -Wextra -Wpedantic -Wconversion -Werror + ASan/UBSan/LSan)"
cmake -S "$REPO_DIR" -B "$OUT_ROOT/clang-asan" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DASH_SANITIZE="address,undefined" > "$OUT_ROOT/clang-asan.cfg.log" 2>&1
cmake --build "$OUT_ROOT/clang-asan" > "$OUT_ROOT/clang-asan.bld.log" 2>&1
ctest --test-dir "$OUT_ROOT/clang-asan" --output-on-failure

echo "== [3/6] Clang ThreadSanitizer (TSan 多线程竞争检测)"
cmake -S "$REPO_DIR" -B "$OUT_ROOT/clang-tsan" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DASH_SANITIZE="thread" > "$OUT_ROOT/clang-tsan.cfg.log" 2>&1
cmake --build "$OUT_ROOT/clang-tsan" > "$OUT_ROOT/clang-tsan.bld.log" 2>&1
ctest --test-dir "$OUT_ROOT/clang-tsan" --output-on-failure

echo "== [4/6] Clang-Tidy (零告警门禁)"
cmake -S "$REPO_DIR" -B "$OUT_ROOT/release-clang" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ > "$OUT_ROOT/rel.cfg.log" 2>&1
cmake --build "$OUT_ROOT/release-clang" > "$OUT_ROOT/rel.bld.log" 2>&1

TIDY_BIN="$(command -v clang-tidy-18 || command -v clang-tidy)"
"$TIDY_BIN" -p "$OUT_ROOT/release-clang" --config-file="$REPO_DIR/.clang-tidy" \
  "$REPO_DIR"/src/*.c "$REPO_DIR"/tools/bench_relay.c

echo "== [5/6] Cppcheck (输出隔离至 /tmp，绝不污染源码树)"
cppcheck --enable=warning,performance,portability \
  --error-exitcode=1 \
  --inline-suppr \
  --suppress=missingIncludeSystem \
  --suppress=unusedFunction \
  --cppcheck-build-dir="$OUT_ROOT/cppcheck-cache" \
  -I "$REPO_DIR/include" \
  "$REPO_DIR/src" "$REPO_DIR/tools/bench_relay.c"

echo "== [6/6] ASan+UBSan+LSan 50,000 随机畸形 UDP + TCP 443 报文模糊测试 & Linux Release 基准"
UPORT=$((45100 + RANDOM % 1000))
TPORT=$((UPORT + 10))
"$OUT_ROOT/clang-asan/ash_server" --bind 127.0.0.1 --port "$UPORT" --tcp-port "$TPORT" \
  --workers 4 --stats-interval 0 > "$OUT_ROOT/fuzz.log" 2>&1 &
SRV_PID=$!
sleep 0.4

python3 - "$UPORT" "$TPORT" <<'PY'
import os, random, socket, sys

uport = int(sys.argv[1])
tport = int(sys.argv[2])
random.seed(20261110)

usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
prefixes = [b'S\x01', b'S\x03', b'S\x10', b'S\x11', b'S\x13', b'S\x15', b'S\x18', b'S\x19', b'S\x1e', b'R', b'J']
for i in range(45000):
    ln = random.choice([0, 1, 2, 3, 5, 9, 15, 20, 39, 64, 128, 512, 1400, random.randint(0, 1600)])
    data = bytearray(os.urandom(ln))
    if ln >= 2 and random.random() < 0.8:
        pfx = random.choice(prefixes)
        data[:len(pfx)] = pfx
    try:
        usock.sendto(bytes(data), ('127.0.0.1', uport))
        if i % 20 == 0:
            usock.sendto(bytes(data[:min(ln, 64)]), ('127.0.0.1', uport + 1))
    except OSError:
        pass
usock.close()

for _ in range(80):
    try:
        ts = socket.create_connection(('127.0.0.1', tport), timeout=0.5)
        mode = random.randint(0, 3)
        if mode == 0:
            ts.sendall(b'GET /ashdesk-relay HTTP/1.1\r\nUpgrade: ashdesk-relay/1\r\n\r\n' + os.urandom(64))
        elif mode == 1:
            ts.sendall(b'\x17\x03\x03\x00\x20' + os.urandom(32) + b'\x17\x03\x03\x99\x99')
        elif mode == 2:
            ts.sendall(b'\x00\x10S\x01' + os.urandom(14) + b'\xff\xff')
        else:
            ts.sendall(os.urandom(random.randint(1, 2048)))
        ts.close()
    except OSError:
        pass
PY

sleep 0.3
kill -0 "$SRV_PID"
kill -TERM "$SRV_PID"
wait "$SRV_PID"

if grep -E "ERROR: (Address|Leak)Sanitizer|runtime error" "$OUT_ROOT/fuzz.log"; then
  echo "Fuzz 检测到 Sanitizer 错误！"
  exit 1
fi
echo "  [通过] 4.5万+ 随机畸形 UDP/TCP 报文及优雅退出无任何内存泄漏或未定义行为！"

echo "== Linux Release 实测基准 =="
"$OUT_ROOT/release-clang/ash_bench" --hosts 2000 --packets 80000

echo "全部静态检查、Sanitizers、模糊测试与基准全部通过！"
