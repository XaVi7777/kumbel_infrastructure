# Kumbel Infrastructure

Шаблон архитектуры Flutter-приложения для студентов Kumbel Lab.

Проект демонстрирует Clean Architecture (без domain-слоя), Firebase + Google Auth, GoRouter, BLoC, локализацию (RU/EN), UI-кит и тему. Каждая папка содержит README с описанием на русском. Код снабжён подробными комментариями.

## Быстрый старт

```bash
# 1. Клонировать репозиторий
git clone <repo-url>
cd kumbel_infrastructure

# 2. Установить зависимости
flutter pub get

# 3. Сгенерировать файлы локализации
flutter gen-l10n

# 4. Запустить
flutter run
```

> **Важно:** для работы Firebase нужен файл `firebase_options.dart` и настроенный проект в [Firebase Console](https://console.firebase.google.com/).

## Структура проекта

```
lib/
├── main.dart                          # Точка входа: Firebase.init → App
├── core/                              # Ядро — не зависит от конкретных фич
│   ├── constants/                     # Глобальные константы (имена, размеры, пути)
│   │   ├── app_constants.dart
│   │   └── asset_paths.dart
│   ├── localization/                  # Документация по локализации
│   │   └── README.md
│   ├── router/                        # GoRouter — навигация между экранами
│   │   ├── app_router.dart
│   │   └── route_names.dart
│   ├── services/                      # Обёртки над Firebase (Auth, Firestore)
│   │   ├── collection_names.dart
│   │   ├── firebase_auth_service.dart
│   │   └── firestore_service.dart
│   ├── theme/                         # Цвета, стили текста, ThemeData
│   │   ├── app_colors.dart
│   │   ├── app_text_styles.dart
│   │   └── app_theme.dart
│   └── utils/                         # Утилиты (логгер)
│       └── logger.dart
├── data/                              # Слой данных
│   ├── local_datasources/             # Локальные источники (пока пусто)
│   ├── models/                        # Модели данных
│   │   └── user_model.dart
│   ├── remote_datasources/            # Удалённые источники (пока пусто)
│   └── repositories/                  # Репозитории (синглтоны)
│       └── auth_repository.dart
├── features/                          # Фичи (экраны)
│   ├── app/                           # Корневой виджет + глобальный BLoC
│   │   ├── bloc/
│   │   │   ├── app_bloc.dart
│   │   │   ├── app_event.dart
│   │   │   └── app_state.dart
│   │   └── ui/
│   │       └── app.dart
│   ├── splash/ui/splash_screen.dart   # Сплэш — проверка авторизации
│   ├── login/ui/login_screen.dart     # Вход через Google
│   └── home/ui/                       # Домашний экран с вкладками
│       ├── home_shell.dart            # ShellRoute + BottomNavigationBar
│       ├── main_tab.dart              # Главная вкладка
│       └── profile_tab.dart           # Профиль + выход
├── l10n/                              # Локализация (intl + .arb)
│   ├── app_en.arb                     # Английские строки
│   ├── app_ru.arb                     # Русские строки
│   └── generated/                     # Сгенерированный код (не редактировать)
├── ui_kit/                            # UI-кит — переиспользуемые компоненты
│   ├── ui_kit.dart                    # Barrel-файл
│   ├── app_button.dart                # Кнопка (primary/secondary/text/danger)
│   └── app_loading_indicator.dart     # Индикатор загрузки
└── widgets/                           # Составные виджеты
    ├── google_sign_in_button.dart     # Кнопка Google Sign-In
    └── user_avatar.dart               # Аватар пользователя
```

## Архитектура

```
┌─────────────────────────────────────────────────┐
│                  Presentation                    │
│  features/ (Screens + BLoC)                      │
│  ui_kit/ (AppButton, AppLoadingIndicator)        │
│  widgets/ (GoogleSignInButton, UserAvatar)        │
├─────────────────────────────────────────────────┤
│                     Data                         │
│  repositories/ (AuthRepository — синглтон)       │
│  models/ (UserModel)                             │
├─────────────────────────────────────────────────┤
│                     Core                         │
│  services/ (FirebaseAuthService, FirestoreService)│
│  router/ (GoRouter)                              │
│  theme/ (AppTheme, AppColors)                    │
│  localization/ (intl + .arb)                     │
│  constants/ (AppConstants, AssetPaths)           │
└─────────────────────────────────────────────────┘
```

## Auth Flow

```
main.dart → Firebase.init → App → BlocProvider<AppBloc> → MaterialApp.router
  → GoRouter initial: '/' (SplashScreen)
    → ждёт 2 сек → проверяет AuthRepository.isLoggedIn
      → true  → context.go('/home/main')
      → false → context.go('/login')
        → тап Google Sign-In → AuthRepository.signInWithGoogle()
          → authStateChanges → AppBloc → authenticated
            → BlocListener → context.go('/home/main')
              → HomeShell (BottomNav)
                → /home/main (MainTab)
                → /home/profile (ProfileTab → Sign Out → context.go('/login'))
```

## Технологии

| Категория | Технология |
|-----------|-----------|
| Фреймворк | Flutter 3.x, Dart 3.x |
| Состояние | BLoC / flutter_bloc |
| Навигация | GoRouter (ShellRoute) |
| Бэкенд | Firebase (Auth, Firestore) |
| Авторизация | Google Sign-In |
| Локализация | intl + .arb (кодогенерация) |
| Тема | Material 3 |

## Ключевые принципы

- **Без магических строк и чисел** — все значения в константах
- **Стили только через Theme** — `Theme.of(context).textTheme`, не `AppTextStyles` напрямую
- **Синглтоны без DI** — `AuthRepository.instance` (приватный конструктор + static final)
- **Подробные комментарии** — каждый файл объясняет «зачем» и «как»
- **README в каждой папке** — навигация по проекту для новичков

## Локализация

Проект поддерживает русский и английский языки. Строки хранятся в `.arb` файлах (`lib/l10n/`), код генерируется автоматически.

```dart
final loc = AppLocalizations.of(context);
Text(loc.loginTitle);        // "Welcome" / "Добро пожаловать"
Text(loc.greeting('Иван'));  // "Hello, Иван!" / "Привет, Иван!"
```

Добавить новый язык: создайте `lib/l10n/app_xx.arb` и запустите `flutter gen-l10n`.

## Требования

- Flutter SDK >= 3.11.0
- Настроенный Firebase-проект (Android/iOS)
- Файл `.env` (опционально, для секретов)
