import 'package:flutter/material.dart';

/// Индикатор загрузки — используется на сплэше, при входе и т.д.
///
/// Это обёртка над стандартным [CircularProgressIndicator],
/// чтобы не дублировать настройки (цвет, размер) в каждом экране.
///
/// Цвет индикатора берётся из [Theme.of(context).colorScheme.primary],
/// а не из [AppColors] напрямую — так он автоматически подстроится
/// под текущую тему (светлую, тёмную или кастомную).
class AppLoadingIndicator extends StatelessWidget {
  /// Размер индикатора (ширина и высота).
  final double size;

  const AppLoadingIndicator({
    super.key,
    this.size = 36,
  });

  @override
  Widget build(BuildContext context) {
    // Берём основной цвет из цветовой схемы темы.
    // Раньше здесь было `AppColors.primary` — это работает,
    // но не адаптируется при смене темы. Правильный подход:
    // всегда обращаться к Theme.of(context).colorScheme.
    final primaryColor = Theme.of(context).colorScheme.primary;

    return SizedBox(
      width: size,
      height: size,
      child: CircularProgressIndicator(
        strokeWidth: 3,
        color: primaryColor,
      ),
    );
  }
}
