# StructScan WinDbg Extension (v3.0)

**StructScan** — высокоскоростное плагин-расширение для отладчика WinDbg (`dbgeng.dll`), предназначенное для **автоматической реконструкции непубличных структур данных** (для которых отсутствуют закрытые PDB-символы, такие как `ntdsai!gAnchor`, `nt!_OBJECT_TYPE`, кастомные структуры драйверов или объекты ядра).

Версия **v3.0** сочетает в себе прямой высокоскоростной анализ виртуальной памяти (`ReadVirtual`), вычисление энтропии Шеннона, байесовскую вероятностную классификацию полей и кросс-референсный анализ множества экземпляров через списки `LIST_ENTRY`.

---

## 🚀 Запуск и Использование в WinDbg

### 1. Загрузка плагина в WinDbg:
```text
0: kd> .load C:\Tools\windbg-agent\structscan.dll
```

### 2. Режимы работы:

#### 🔹 Режим 1: Байесовский анализ одиночной структуры (`!structscan`)
Сканирует память структуры и классифицирует каждое 8-байтовое поле (указатели, UNICODE_STRING, ASCII, PoolTag, Integer, Flags, Handle, LIST_ENTRY):
```text
0: kd> !structscan nt!PsInitialSystemProcess 0x400
0: kd> !structscan 0xfffff802ac809ab0 0x200
```

#### 🔹 Режим 2: Кросс-референсный анализ списка объектов (`!structscan list`)
Автоматически находит смещение `LIST_ENTRY`, обходит цепочку связанных объектов (до 64 экземпляров) и анализирует **постоянство типов полей** на каждом смещении:
```text
0: kd> !structscan list nt!PsActiveProcessHead 0x800
```

#### 🔹 Режим 3: Тепловая карта энтропии Шеннона (`!structscan entropy`)
Отображает распределение энтропии в 16-байтовых окнах (позволяет быстро обнаружить указатели, шифрованные поля, теги и паддинг):
```text
0: kd> !structscan entropy nt!PsInitialSystemProcess 0x200
```

#### 🔹 Безопасная выгрузка:
```text
0: kd> !structscan unload
[+] Run: .unload structscan
```

---

## 📊 Пример Вывода (v3.0)

```text
0: kd> !structscan nt!PsInitialSystemProcess 0x400
[+] Target Address: 0xfffff802ac809ab0 (Scan Window: 0x400 bytes)
[+] Algorithm: Bayesian Field Classifier v3.0 (Shannon Entropy + Multi-feature)

  Offset    Address               Type              Entropy  Confidence  Annotation
  --------  --------------------  ----------------  -------  ----------  ------------------------------
  +0x0038  [0xfffff802ac809ae8]  Integer           H=0.54  [#####---]  0x4 (4)
  +0x0080  [0xfffff802ac809b30]  Pointer           H=2.50  [########]  nt!_guard_eh_cont_table <PERF> (nt+0x0)
  +0x0090  [0xfffff802ac809b40]  Pointer           H=2.75  [########]  nt!KiInitialProcess
  +0x00c0  [0xfffff802ac809b70]  LIST_ENTRY        H=2.75  [#####---]  Flink=0xfffff802ac809b70 Blink=0xfffff802ac809b70
  +0x00c8  [0xfffff802ac809b78]  Pointer           H=2.75  [########]  nt!PpmPerfDomainHead
  +0x0280  [0xfffff802ac809d30]  Pointer           H=2.75  [########]  nt!WmipDefaultAccessSecurityDescriptor

[+] Complete: 81 fields identified (confidence > 25%)
```

---

## 📁 Структура Проекта

```text
structscan/
├── include/
│   └── structscan.h      # Интеллектуальный классификатор, энтропия, кросс-референс
├── src/
│   └── Main.cpp          # Реализация команд !structscan, !structscan list, !structscan entropy
├── bin/
│   ├── structscan_arm64.dll  # Native ARM64 (AArch64)
│   ├── structscan_x64.dll    # Native x64 (AMD64)
│   └── structscan_x86.dll    # Native x86 (WOW64)
├── CMakeLists.txt        # Скрипт сборки CMake
├── structscan.vcxproj   # Visual Studio 2022/2026 Project
└── README.md
```

---

## 🔨 Сборка из Исходников (MSVC / CMake)

### Мультиархитектурная сборка MSVC:
```cmd
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" arm64
cl.exe /std:c++17 /O2 /EHsc /MD /LD /Iinclude src\Main.cpp /link dbgeng.lib dbghelp.lib /OUT:bin\structscan_arm64.dll
```

### CMake:
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

---

## 🔬 Ключевые Алгоритмы v3.0

1. **Пакетное прямое чтение памяти (Bulk DMA Read)** — `ReadVirtual` считывает всё окно памяти структуры за один запрос (~1 мкс) напрямую в L1-кэш.
2. **Энтропия Шеннона (Shannon Entropy)** — вычисляет информационную энтропию $H$ каждого 8-байтового блока для фильтрации случайного шума и распознавания паддингов.
3. **Байесовский вероятностный классификатор** — взвешивает 11 физических признаков поля по 9 классам типов данных с расчетом вероятности уверенности (Confidence Score `[########]`).
4. **Кросс-референс по спискам (`LIST_ENTRY`)** — находит связи между объектами одного типа в памяти и определяет реальное предназначение полей по их воспроизводимости на разных экземплярах.
5. **Форензика NT Pool Tags** — автоматическое распознавание 4-байтовых тегов пулов (`Proc`, `Thre`, `File`, `Driv`, `Devi`, `Key ` и др.).
