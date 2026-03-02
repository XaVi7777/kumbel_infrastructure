# core/theme/

Визуальная тема приложения — цвета, шрифты, стили.

| Файл | Описание |
|------|----------|
| `app_colors.dart` | Палитра цветов (`AppColors.primary`, `.textPrimary` и т.д.) |
| `app_text_styles.dart` | Стили текста — используются **только** внутри `app_theme.dart` для сборки `ThemeData` |
| `app_theme.dart` | Сборка `ThemeData` из цветов и стилей |

## Как использовать

```dart
// Цвета — через colorScheme темы (предпочтительный способ в виджетах):
final colorScheme = Theme.of(context).colorScheme;
Container(color: colorScheme.primary)

// Стили текста — ВСЕГДА через тему (никогда через AppTextStyles напрямую):
final textTheme = Theme.of(context).textTheme;
Text('Заголовок', style: textTheme.headlineLarge)
Text('Обычный текст', style: textTheme.bodyLarge)
```

## Важно

- `AppTextStyles` **нельзя** импортировать в экранах и виджетах.
  Он существует только для того, чтобы задать стили в `ThemeData`.
- В виджетах используйте `Theme.of(context).textTheme` — так стили
  автоматически адаптируются при смене темы (светлая/тёмная).
- Аналогично для цветов: предпочитайте `Theme.of(context).colorScheme`
  вместо прямых ссылок на `AppColors`.

## Как добавить тёмную тему

Создайте метод `AppTheme.dark` по аналогии с `AppTheme.light`
и переключайте в `MaterialApp(theme: ..., darkTheme: ...)`.
