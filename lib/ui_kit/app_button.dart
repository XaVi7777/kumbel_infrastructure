import 'package:flutter/material.dart';

/// Основная кнопка приложения с несколькими вариантами оформления.
///
/// Зачем свой виджет, а не просто `ElevatedButton`?
/// 1. Единый стиль — не надо копировать `style:` везде.
/// 2. Встроенный индикатор загрузки ([isLoading]).
/// 3. Если дизайн изменится — меняем только здесь.
///
/// Варианты кнопок (именованные конструкторы):
/// - [AppButton.primary]   — основное действие (заливка основным цветом).
/// - [AppButton.secondary] — второстепенное действие (обводка без заливки).
/// - [AppButton.text]      — текстовая кнопка (без фона и обводки).
/// - [AppButton.danger]    — опасное действие (красный цвет ошибки).
///
/// Все варианты поддерживают [isLoading] — показывает спиннер вместо текста.
/// Стили берутся из [Theme], а не из констант — так кнопки автоматически
/// адаптируются при смене темы (светлая/тёмная).
class AppButton extends StatelessWidget {
  /// Текст на кнопке.
  final String text;

  /// Колбэк при нажатии. Если `null` — кнопка неактивна.
  final VoidCallback? onPressed;

  /// Показывать ли индикатор загрузки вместо текста.
  final bool isLoading;

  /// Вариант оформления кнопки (определяет цвета и стиль).
  final _AppButtonVariant _variant;

  // ── Именованные конструкторы ──────────────────────────────────

  /// Основное действие — кнопка с заливкой основным цветом (primary).
  ///
  /// Используйте для главных действий на экране:
  /// сохранить, отправить, подтвердить.
  const AppButton.primary({
    super.key,
    required this.text,
    required this.onPressed,
    this.isLoading = false,
  }) : _variant = _AppButtonVariant.primary;

  /// Второстепенное действие — кнопка с обводкой, без заливки.
  ///
  /// Используйте для альтернативных действий:
  /// отмена, назад, «может быть позже».
  const AppButton.secondary({
    super.key,
    required this.text,
    required this.onPressed,
    this.isLoading = false,
  }) : _variant = _AppButtonVariant.secondary;

  /// Текстовая кнопка — без фона и обводки.
  ///
  /// Используйте для малозаметных действий:
  /// «пропустить», «подробнее», ссылки в тексте.
  const AppButton.text({
    super.key,
    required this.text,
    required this.onPressed,
    this.isLoading = false,
  }) : _variant = _AppButtonVariant.text;

  /// Опасное действие — кнопка красного цвета (error).
  ///
  /// Используйте для деструктивных действий:
  /// удалить аккаунт, выйти, отменить подписку.
  const AppButton.danger({
    super.key,
    required this.text,
    required this.onPressed,
    this.isLoading = false,
  }) : _variant = _AppButtonVariant.danger;

  /// Дефолтный конструктор — эквивалент [AppButton.primary].
  ///
  /// Оставлен для обратной совместимости: если в коде уже есть
  /// `AppButton(text: ..., onPressed: ...)`, он продолжит работать.
  const AppButton({
    super.key,
    required this.text,
    required this.onPressed,
    this.isLoading = false,
  }) : _variant = _AppButtonVariant.primary;

  @override
  Widget build(BuildContext context) {
    // Берём цвета из темы — это гарантирует корректную работу
    // с любой цветовой схемой (светлой, тёмной, кастомной).
    final colorScheme = Theme.of(context).colorScheme;

    // Во время загрузки блокируем нажатие.
    final effectiveOnPressed = isLoading ? null : onPressed;

    // Виджет-индикатор загрузки, одинаковый для всех вариантов.
    // Цвет спиннера подбирается под вариант кнопки, чтобы
    // он был виден на её фоне.
    Widget loadingIndicator(Color color) {
      return SizedBox(
        width: 20,
        height: 20,
        child: CircularProgressIndicator(
          strokeWidth: 2,
          color: color,
        ),
      );
    }

    // В зависимости от варианта возвращаем нужный тип кнопки.
    switch (_variant) {
      case _AppButtonVariant.primary:
        return ElevatedButton(
          onPressed: effectiveOnPressed,
          child: isLoading
              ? loadingIndicator(colorScheme.onPrimary)
              : Text(text),
        );

      case _AppButtonVariant.secondary:
        return OutlinedButton(
          onPressed: effectiveOnPressed,
          child: isLoading
              ? loadingIndicator(colorScheme.primary)
              : Text(text),
        );

      case _AppButtonVariant.text:
        return TextButton(
          onPressed: effectiveOnPressed,
          child: isLoading
              ? loadingIndicator(colorScheme.primary)
              : Text(text),
        );

      case _AppButtonVariant.danger:
        return ElevatedButton(
          onPressed: effectiveOnPressed,
          // Переопределяем цвета для «опасной» кнопки:
          // фон — цвет ошибки, текст — контрастный цвет на ошибке.
          style: ElevatedButton.styleFrom(
            backgroundColor: colorScheme.error,
            foregroundColor: colorScheme.onError,
          ),
          child: isLoading
              ? loadingIndicator(colorScheme.onError)
              : Text(text),
        );
    }
  }
}

/// Варианты оформления кнопки (внутренний enum).
///
/// Используется только внутри [AppButton] — снаружи
/// выбор варианта происходит через именованные конструкторы.
enum _AppButtonVariant {
  /// Основное действие (ElevatedButton с primary-цветом).
  primary,

  /// Второстепенное действие (OutlinedButton).
  secondary,

  /// Текстовая кнопка (TextButton).
  text,

  /// Опасное действие (ElevatedButton с error-цветом).
  danger,
}
