# StructScan WinDbg Extension (v1.5)

**StructScan** — это расширение плагин для отладчика WinDbg (`dbgeng.dll`), предназначенный для **автоматического сканирования непубличных структур данных** (для которых отсутствуют закрытые символы PDB, например `ntdsai!gAnchor`, `nt!_OBJECT_TYPE` или кастомные структуры драйверов) и поиска полезной информации (строк Unicode/ANSI, указателей на функции и т.д.).

Модернизировано на C++17 RAII с интеграцией `IDebugOutputCallbacks2` и поддержкой WinDbg MCP / WinDbg Preview / WinDbg Classic.

---

## 🚀 Запуск и Использование в WinDbg

### 1. Загрузка плагина в сессии WinDbg:
```text
.load C:\Tools\windbg-agent\structscan.dll
```

### 2. Запуск сканирования структуры по имени символа:
```text
!structscan ntdsai!gAnchor
```

### 3. Запуск сканирования по полному виртуальному адресу с ограничением смещения:
```text
!structscan 0x7ffc64da6000 0x200
```

---

## 🛠️ Пример Вывода Плагина

```text
Module name: ntdsai
Image base: 0x00007FFC64DA0000
Memory Size: 0x820000

[+] Target Address: 0x00007FFC64DA6000 (Max Scan: 0x1000 bytes)
[+] Scanning for Strings, UNICODE_STRINGs, and Pointers...

  +0x0010 [0x00007FFC64DA6010] (dS): \Device\HarddiskVolume3\Windows\NTDS
  +0x0048 [0x00007FFC64DA6048] (ds): ActiveDirectoryInstance01
  +0x0080 [0x00007FFC64DA6080] (Pointer): 0x00007FFC64DA8120 -> ntdsai!gAnchor_Callback+0x0
```

---

## 🔨 Сборка из Исходников (MSVC / CMake)

### Вариант 1: MSVC Command Prompt (x64)
```cmd
cl /nologo /LD /EHsc /std:c++17 /O2 /Fe:structscan.dll Main.cpp dbgeng.lib user32.lib
```

### Вариант 2: CMake
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

---

## 🔬 Архитектурные Улучшения v1.5 (C++17)

- **Без Flipping Callback:** Класс `OutputCaptureCallback` устанавливает перехватчик вывода `IDebugOutputCallbacks2` **один раз** по шаблону RAII и автоматически восстанавливает оригинальный callback WinDbg при завершении.
- **Поддержка WinDbg MCP & Remote Debugging:** Убраны локальные Win32 UI вызовы (`GetAsyncKeyState`), прерывание сканирования работает через нативный метод отладчика `DebugControl->GetInterrupt()` (Ctrl+C).
- **Разрешение Указателей:** Автоматически распознает указатели на смещения других модулей через `IDebugDataSpaces4` и `GetNameByOffsetWide`.
