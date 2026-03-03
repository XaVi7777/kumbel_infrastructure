import 'package:logger/logger.dart';

class AppLogger {
  static final Logger _logger = Logger(
    printer: PrettyPrinter(
      methodCount: 1,
      errorMethodCount: 5,
      lineLength: 80,
      colors: true,
      printEmojis: true,
    ),
  );

  /// Информационное сообщение
  static void info(String message) {
    _logger.i(message);
  }

  /// Предупреждение
  static void warning(String message) {
    _logger.w(message);
  }

  /// Ошибка
  static void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
  }) {
    _logger.e(
      message,
      error: error,
      stackTrace: stackTrace,
    );
  }

  /// Debug (полезно для разработки)
  static void debug(String message) {
    _logger.d(message);
  }
}