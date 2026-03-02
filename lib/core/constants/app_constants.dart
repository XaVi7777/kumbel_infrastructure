/// Глобальные константы приложения.
///
/// Здесь собраны все «магические» значения, чтобы не разбрасывать
/// числа и строки по коду. Если нужно что-то поменять — меняем
/// только здесь, и изменения подхватятся везде.
class AppConstants {
  // ── Общие ──────────────────────────────────────────────────────
  /// Название приложения (отображается в AppBar, заголовке и т.д.)
  static const String appName = 'Kumbel';

  // ── Тайминги ───────────────────────────────────────────────────
  /// Сколько секунд показываем сплэш-экран перед переходом.
  static const int splashDelaySeconds = 2;

  // ── Навигация (индексы вкладок BottomNavigationBar) ────────────
  /// Индекс вкладки «Главная».
  static const int mainTabIndex = 0;

  /// Индекс вкладки «Профиль».
  static const int profileTabIndex = 1;

  // ── Размеры ────────────────────────────────────────────────────
  /// Размер аватара пользователя (радиус CircleAvatar).
  static const double avatarRadius = 48;

  /// Ширина кнопки Google Sign-In.
  static const double googleButtonWidth = 280;

  /// Высота кнопки Google Sign-In.
  static const double googleButtonHeight = 48;

  /// Размер логотипа Google внутри кнопки.
  static const double googleLogoSize = 24;

  // ── Отступы ────────────────────────────────────────────────────
  /// Стандартный отступ между элементами.
  static const double defaultPadding = 16;

  /// Маленький отступ.
  static const double smallPadding = 8;

  /// Большой отступ.
  static const double largePadding = 24;
}
