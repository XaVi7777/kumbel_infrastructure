# core/router/

Навигация между экранами (GoRouter).

| Файл | Описание |
|------|----------|
| `route_names.dart` | Константы путей (`/login`, `/home/main`) и имён маршрутов |
| `app_router.dart` | Конфигурация GoRouter — все маршруты и ShellRoute |

## Структура маршрутов

```
/               → SplashScreen
/login          → LoginScreen
/home           → HomeShell (ShellRoute + BottomNavigationBar)
  /home/main    → MainTab
  /home/profile → ProfileTab
```

## Как добавить новый экран

1. Добавьте путь и имя в `route_names.dart`.
2. Добавьте `GoRoute` в `app_router.dart`.
3. Используйте `context.go(RouteNames.xxx)` для перехода.
