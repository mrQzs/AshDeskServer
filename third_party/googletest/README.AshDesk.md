# GoogleTest（第三方）

- 版本：1.18.0，vcpkg 端口 `gtest`，vcpkg 基线 `9eec002df1cd109f8f104cd966a763daf9751489`（与 Opus、OpenSSL 同一基线）
- 许可：BSD-3（`LICENSE`），只链进测试程序 `adrd_gtest`，不随产品发布
- 用途：单元测试框架（AGENTS.md 代码质量标准第 3 条）。新写的单元测试用它（`tests/gtest/`），老的 C 测试逐个迁过来；CTest 按用例逐个列出（`gtest_discover_tests`）
- 仓库里只放这份说明和 `LICENSE`；`include/` 和 `lib/` 不进仓库（`.gitignore`）。Linux 上用系统的包（Ubuntu：`libgtest-dev`）

## 取得（Windows）

用 VS 2022 自带的 vcpkg（清单模式），triplet `x64-windows-static-md`（静态库、动态 CRT，和我们的程序一致）：

```
vcpkg.json（放在任意一个空目录里，比如 build/vcpkg-gtest）:
{ "name": "adrd-gtest", "version": "0.1.0",
  "builtin-baseline": "9eec002df1cd109f8f104cd966a763daf9751489",
  "dependencies": [ "gtest" ] }

"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\vcpkg\vcpkg.exe" install --triplet x64-windows-static-md ^
  --x-buildtrees-root=D:/Code/AshDesk/build/vcpkg/gbt --x-packages-root=D:/Code/AshDesk/build/vcpkg/gpk ^
  --x-install-root=D:/Code/AshDesk/build/vcpkg/ginst
```

产物（`build/vcpkg/ginst/x64-windows-static-md/`）拷到这里：

- `include/gtest/` → `include/gtest/`
- `lib/gtest.lib`、`lib/manual-link/gtest_main.lib` → `lib/`
- `share/gtest/copyright` → `LICENSE`

sha256（这次构建）：`gtest.lib` `1a643fb7881434de0e8b281ec1a82650d2c36cf500df69a8851f42e107eb0e2c`，
`gtest_main.lib` `e0b9b56b7ca67c66c406e42b6b4af50ba55a6658deb3cf456a24a9a5477007b2`。

没有这些文件时 CMake 照常配置，只是不编 `adrd_gtest`（配置时给警告）。

MSVC 的 ASan 构建（`-DADRD_SANITIZE=address`）链接这份没开 ASan 的 `gtest.lib`：CMake 给 C++ 定义了
`_DISABLE_VECTOR_ANNOTATION` / `_DISABLE_STRING_ANNOTATION`，否则 STL 的容器注解两边不一致，链接时报 annotate_string 不匹配。
