# core/utils/

Вспомогательные утилиты.

| Файл | Описание |
|------|----------|
| `logger.dart` | Простой логгер (`AppLogger.info`, `.warning`, `.error`) |

## Логгер

Использует `dart:developer` — сообщения видны при `flutter run`,
но **не попадают** в релизную сборку (в отличие от `print`).

```dart
AppLogger.info('Пользователь вошёл');
AppLogger.error('Ошибка загрузки', error: e, stackTrace: st);
```
