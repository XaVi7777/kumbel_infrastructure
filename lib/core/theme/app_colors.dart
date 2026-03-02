import 'package:flutter/material.dart';

/// Палитра цветов приложения.
///
/// Все цвета определены здесь — в виджетах используем
/// только `AppColors.xxx`, никаких `Color(0xFF...)` в коде.
class AppColors {
  // ── Основные ───────────────────────────────────────────────────
  /// Главный цвет бренда.
  static const Color primary = Color(0xFF6750A4);

  /// Цвет текста/иконок на primary-фоне.
  static const Color onPrimary = Colors.white;

  /// Вторичный акцентный цвет.
  static const Color secondary = Color(0xFF625B71);

  /// Цвет текста/иконок на secondary-фоне.
  static const Color onSecondary = Colors.white;

  // ── Фоны ───────────────────────────────────────────────────────
  /// Основной фон экранов.
  static const Color background = Color(0xFFFFFBFE);

  /// Фон поверхностей (карточки, bottom sheet и т.д.).
  static const Color surface = Color(0xFFFFFBFE);

  /// Цвет ошибок.
  static const Color error = Color(0xFFB3261E);

  // ── Текст ──────────────────────────────────────────────────────
  /// Основной цвет текста.
  static const Color textPrimary = Color(0xFF1C1B1F);

  /// Второстепенный цвет текста (подписи, хинты).
  static const Color textSecondary = Color(0xFF49454F);

  // ── Прочие ─────────────────────────────────────────────────────
  /// Цвет разделителей.
  static const Color divider = Color(0xFFCAC4D0);

  /// Цвет неактивных иконок в навигации.
  static const Color inactive = Color(0xFF79747E);
}
