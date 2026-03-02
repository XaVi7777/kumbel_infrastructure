import 'package:flutter/material.dart';

import 'app_colors.dart';

/// Стили текста, используемые в приложении.
///
/// Называем стили по смыслу (headline, body, label),
/// а не по размеру — так проще поддерживать единообразие.
class AppTextStyles {
  // ── Заголовки ──────────────────────────────────────────────────
  /// Крупный заголовок экрана.
  static const TextStyle headlineLarge = TextStyle(
    fontSize: 28,
    fontWeight: FontWeight.bold,
    color: AppColors.textPrimary,
  );

  /// Средний заголовок (секции, карточки).
  static const TextStyle headlineMedium = TextStyle(
    fontSize: 22,
    fontWeight: FontWeight.w600,
    color: AppColors.textPrimary,
  );

  // ── Основной текст ─────────────────────────────────────────────
  /// Обычный текст.
  static const TextStyle bodyLarge = TextStyle(
    fontSize: 16,
    fontWeight: FontWeight.normal,
    color: AppColors.textPrimary,
  );

  /// Мелкий текст (подписи, детали).
  static const TextStyle bodySmall = TextStyle(
    fontSize: 14,
    fontWeight: FontWeight.normal,
    color: AppColors.textSecondary,
  );

  // ── Кнопки и лейблы ───────────────────────────────────────────
  /// Текст на кнопках.
  static const TextStyle button = TextStyle(
    fontSize: 16,
    fontWeight: FontWeight.w600,
    color: AppColors.onPrimary,
  );

  /// Мелкий лейбл (чипсы, бейджи).
  static const TextStyle label = TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w500,
    color: AppColors.textSecondary,
  );
}
