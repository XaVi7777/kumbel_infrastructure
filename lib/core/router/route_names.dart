/// Константы имён и путей маршрутов.
///
/// Используем константы вместо строк в коде, чтобы:
/// 1. Автодополнение IDE подсказывало имена.
/// 2. Опечатка вызовет ошибку компиляции, а не баг в рантайме.
/// 3. Переименование маршрута — в одном месте.
class RouteNames {
  // ── Пути (paths) — используем в context.go() ─────────────────
  /// Сплэш-экран (начальный маршрут).
  static const String splash = '/';

  /// Экран входа.
  static const String login = '/login';

  /// Вкладка «Главная».
  static const String main = '/home/main';

  /// Вкладка «Профиль».
  static const String profile = '/home/profile';

  // ── Имена (names) — используем в GoRoute(name: ...) ──────────
  static const String splashName = 'splash';
  static const String loginName = 'login';
  static const String mainName = 'main';
  static const String profileName = 'profile';
}
