import 'package:flutter/material.dart';

import '../core/constants/app_constants.dart';

/// Аватар пользователя — переиспользуемый виджет.
///
/// Отображает фото пользователя в круглой рамке.
/// Если URL фото пустой — показывает иконку-заглушку (Icons.person).
///
/// Зачем выносить в отдельный виджет?
/// 1. **DRY** (Don't Repeat Yourself) — аватар используется на нескольких
///    экранах (главная, профиль). Без выделения в виджет код дублируется.
/// 2. **Единый стиль** — если нужно изменить оформление аватара
///    (добавить рамку, тень, бейдж), меняем только здесь.
/// 3. **Тестируемость** — можно написать отдельный widget-тест.
///
/// Пример использования:
/// ```dart
/// UserAvatar(photoUrl: user.photoUrl)
/// UserAvatar(photoUrl: user.photoUrl, radius: 32)
/// ```
class UserAvatar extends StatelessWidget {
  /// URL фото пользователя.
  ///
  /// Если строка пустая — отображается иконка-заглушка.
  final String photoUrl;

  /// Радиус круглого аватара.
  ///
  /// По умолчанию используется [AppConstants.avatarRadius].
  /// Можно передать другое значение для уменьшенной версии (например, в списке).
  final double radius;

  const UserAvatar({
    super.key,
    required this.photoUrl,
    this.radius = AppConstants.avatarRadius,
  });

  @override
  Widget build(BuildContext context) {
    // Берём цвет иконки-заглушки из цветовой схемы темы.
    // Так при смене темы (светлая/тёмная) иконка адаптируется автоматически.
    final colorScheme = Theme.of(context).colorScheme;

    return CircleAvatar(
      radius: radius,
      // Если URL не пустой — загружаем фото из сети.
      // NetworkImage загружает картинку асинхронно и кэширует её.
      backgroundImage: photoUrl.isNotEmpty ? NetworkImage(photoUrl) : null,
      // Если фото нет — показываем иконку-заглушку.
      // Размер иконки равен радиусу аватара, чтобы смотрелось пропорционально.
      child: photoUrl.isEmpty
          ? Icon(
              Icons.person,
              size: radius,
              color: colorScheme.onSurfaceVariant,
            )
          : null,
    );
  }
}
