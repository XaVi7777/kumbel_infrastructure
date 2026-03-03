name: kumbel_infrastructure
description: "Шаблон архитектуры Flutter-приложения для студентов."
publish_to: 'none'
version: 1.0.0+1

environment:
  sdk: ^3.11.0

dependencies:
  flutter:
    sdk: flutter
  flutter_localizations: # Поддержка нескольких языков (локализация)
    sdk: flutter

  # UI
  cupertino_icons: ^1.0.8 # Иконки в стиле iOS
  flutter_svg: ^2.2.3 # Отображение SVG-картинок и иконок
  cached_network_image: ^3.4.1 # Загрузка и кэширование картинок из интернета
  flutter_animate: ^4.5.2 # Простые и красивые анимации для виджетов
  gap: ^3.0.1 # Виджет-отступ — замена SizedBox(height: 16) на Gap(16)
  logger: ^2.6.2

  # Управление состоянием
  bloc: ^9.2.0 # Бизнес-логика приложения (паттерн BLoC)
  flutter_bloc: ^9.1.1 # Виджеты для связи BLoC с интерфейсом

  # Firebase — серверная часть приложения
  firebase_core: ^4.4.0 # Ядро Firebase — нужно для работы всех Firebase-сервисов
  firebase_auth: ^6.1.4 # Авторизация пользователей (вход/регистрация)
  cloud_firestore: ^6.1.2 # База данных Firestore — хранение данных на сервере
  firebase_storage: ^13.0.6 # Хранение файлов в облаке (фото, документы)
  google_sign_in: ^7.2.0 # Вход через Google-аккаунт

  # Навигация
  go_router: ^17.1.0 # Роутер — переходы между экранами приложения

  # Формы
  flutter_form_builder: ^10.3.0 # Удобное создание форм (ввод данных)
  form_builder_validators: ^11.3.0 # Валидация полей формы (проверка введённых данных)

  # Утилиты
  equatable: ^2.0.8 # Удобное сравнение объектов (нужно для BLoC-состояний)
  intl: ^0.20.2 # Форматирование дат, чисел и валют
  flutter_dotenv: ^6.0.0 # Чтение секретов и настроек из .env файла
  shared_preferences: ^2.5.4 # Локальное хранилище (сохранить тему, язык, токен)
  connectivity_plus: ^7.0.0 # Проверка интернет-соединения
  url_launcher: ^6.3.2 # Открытие ссылок, email и телефона из приложения
  image_picker: ^1.2.1 # Выбор фото из галереи или камеры

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^5.0.0 # Правила линтера — помогает писать чистый код

  # Генерация иконки и сплэш-экрана
  flutter_native_splash: ^2.4.7 # Экран загрузки при запуске приложения
  flutter_launcher_icons: ^0.14.4 # Генерация иконки приложения для Android и iOS

flutter:
  # Включаем автоматическую генерацию локализации из .arb файлов.
  # При каждом `flutter pub get` или `flutter run` Flutter проверит .arb файлы
  # и сгенерирует Dart-код для доступа к переводам.
  generate: true

  uses-material-design: true

  # Ассеты — картинки, иконки, SVG и другие файлы.
  assets:
    - assets/svg/
