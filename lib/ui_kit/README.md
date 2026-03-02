# ui_kit/

UI-кит — переиспользуемые UI-компоненты приложения.

| Файл | Описание |
|------|----------|
| `ui_kit.dart` | Barrel-файл — импортирует все компоненты одной строкой |
| `app_button.dart` | Основная кнопка с поддержкой состояния загрузки |
| `app_loading_indicator.dart` | Индикатор загрузки (обёртка над `CircularProgressIndicator`) |

## Как использовать

```dart
import 'package:kumbel_infrastructure/ui_kit/ui_kit.dart';

// Кнопка:
AppButton(text: 'Сохранить', onPressed: () {})

// С загрузкой:
AppButton(text: 'Сохранить', onPressed: _save, isLoading: true)

// Индикатор:
AppLoadingIndicator()
```

## Чем UI-кит отличается от widgets/?

- **ui_kit/** — универсальные компоненты (кнопка, индикатор, поле ввода).
- **widgets/** — составные виджеты, привязанные к бизнес-логике (кнопка Google Sign-In).
