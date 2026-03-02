import 'dart:developer' as dev;

/// Простой логгер для отладки.
///
/// Использует `dart:developer` → сообщения видны в консоли
/// при запуске через `flutter run`, но **не попадают** в
/// релизную сборку (в отличие от `print`).
///
/// Пример:
/// ```dart
/// AppLogger.info('Пользователь вошёл');
/// AppLogger.error('Ошибка загрузки', error: e);
/// ```
class AppLogger {
  /// Информационное сообщение.
  static void info(String message) {
    dev.log('💡 $message', name: 'APP');
  }

  /// Предупреждение.
  static void warning(String message) {
    dev.log('⚠️ $message', name: 'APP');
  }

  /// Ошибка (можно передать объект ошибки и стек-трейс).
  static void error(String message, {Object? error, StackTrace? stackTrace}) {
    dev.log(
      '❌ $message',
      name: 'APP',
      error: error,
      stackTrace: stackTrace,
    );
  }
}
