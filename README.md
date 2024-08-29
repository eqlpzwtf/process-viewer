# Process Viewer App

The **Process Viewer App** is a Python-based graphical user interface (GUI) application that allows users to view and manage running processes on their system. This tool provides an intuitive interface for viewing process information, scanning process memory for strings, and filtering those strings based on user input. It is especially useful for developers, system administrators, and anyone needing to inspect memory contents for specific processes.

**Attention: The program is intended only for use on the Linux operating system.**

## Features

- **Process List**: Displays all currently running processes with their PID and name.
- **Base Address Display**: Optionally display the base memory addresses for each process.
- **Memory Scanning**: Scan the memory of selected processes to extract ASCII strings of length 4 or more.
- **Filtered Search**: Filter scanned strings by specific keywords.
- **Context Menu**: Right-click on any process in the list to perform memory scans or view scanned strings.
- **Real-time Updates**: Refresh the process list to ensure up-to-date information.

## Requirements

- **Python 3.x**
- **psutil**: For accessing system process information.
- **tkinter**: For creating the graphical user interface.

You can install `psutil` using pip:

```bash
pip install psutil
```

## Usage

1. **Run the Application**: 
   Make sure to run the program with superuser privileges, as certain system operations (like reading process memory) require elevated permissions.

   ```bash
   sudo python3 process_viewer.py
   ```

2. **View and Manage Processes**: 
   After launching the application, you will see a list of all running processes. You can refresh the list by clicking the "Refresh" button.

3. **Scan Memory**: 
   Right-click on a process in the list and choose "Scan Memory" to scan its memory for strings.

4. **View Scanned Strings**: 
   After scanning memory, you can view the scanned strings by right-clicking on the process and selecting "View Scanned Strings."

5. **Filter Strings**: 
   Use the filter option to search for specific keywords within the scanned strings.

## Screenshots

*Insert screenshots of your application here to show the process list, memory scanning, and filtering.*

## Known Issues

- Memory scanning requires superuser privileges.
- Some processes may not be accessible for scanning, depending on the system's permissions and security policies.

## Contributions

Contributions are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request.

r

# Process Viewer App

**Process Viewer App** — это графическое приложение на Python, которое позволяет пользователям просматривать и управлять запущенными процессами на их системе. Этот инструмент предоставляет интуитивно понятный интерфейс для просмотра информации о процессах, сканирования памяти процессов на наличие строк и фильтрации этих строк по введенному пользователем тексту. Программа будет полезна разработчикам, системным администраторам и всем, кто нуждается в инспектировании содержимого памяти для конкретных процессов.

**Внимание: программа предназначена только для работы в операционной системе Linux.**

## Основные функции

- **Список процессов**: Отображает все текущие запущенные процессы с их PID и именем.
- **Отображение базового адреса**: Опционально отображает базовые адреса памяти для каждого процесса.
- **Сканирование памяти**: Сканирует память выбранных процессов и извлекает ASCII строки длиной 4 символа и более.
- **Фильтрация строк**: Фильтрует отсканированные строки по заданным ключевым словам.
- **Контекстное меню**: Кликните правой кнопкой мыши по любому процессу в списке, чтобы выполнить сканирование памяти или просмотреть отсканированные строки.
- **Обновление в реальном времени**: Обновите список процессов, чтобы получить актуальную информацию.

## Требования

- **Python 3.x**
- **psutil**: Для доступа к информации о системных процессах.
- **tkinter**: Для создания графического интерфейса.

Установить `psutil` можно с помощью pip:

```bash
pip install psutil
```

## Использование

1. **Запуск приложения**: 
   Убедитесь, что программа запущена с привилегиями суперпользователя, так как для выполнения некоторых операций (например, чтения памяти процессов) требуются повышенные права.

   ```bash
   sudo python3 process_viewer.py
   ```

2. **Просмотр и управление процессами**: 
   После запуска приложения вы увидите список всех запущенных процессов. Обновить список можно, нажав на кнопку "Refresh".

3. **Сканирование памяти**: 
   Щелкните правой кнопкой мыши по процессу в списке и выберите "Scan Memory", чтобы выполнить сканирование памяти на наличие строк.

4. **Просмотр отсканированных строк**: 
   После сканирования памяти вы можете просмотреть найденные строки, щелкнув правой кнопкой мыши по процессу и выбрав "View Scanned Strings".

5. **Фильтрация строк**: 
   Используйте функцию фильтрации, чтобы искать конкретные ключевые слова в отсканированных строках.

## Скриншоты

*Добавьте скриншоты вашего приложения, чтобы показать список процессов, сканирование памяти и фильтрацию.*

## Известные проблемы

- Для сканирования памяти требуются права суперпользователя.
- Некоторые процессы могут быть недоступны для сканирования в зависимости от настроек прав и политики безопасности системы.

## Вклад

Вклады приветствуются! Если у вас есть предложения по улучшению или добавлению новых функций, не стесняйтесь открывать issue или отправлять pull request.
