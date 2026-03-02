# Локализация (intl + .arb)

Проект использует стандартный подход Flutter к локализации:
**пакет `intl`** + файлы `.arb` (Application Resource Bundle) + кодогенерация.

## Структура файлов

```
lib/
  l10n/
    app_en.arb          <- Английские строки (шаблонный файл)
    app_ru.arb          <- Русские строки
    generated/           <- Автоматически сгенерированный код (НЕ РЕДАКТИРОВАТЬ)
      app_localizations.dart
      app_localizations_en.dart
      app_localizations_ru.dart
l10n.yaml               <- Настройки генератора (в корне проекта)
```

## Как это работает

1. **`.arb` файлы** — JSON-подобные файлы с переводами. Каждый ключ — это
   название строки, значение — перевод. В шаблонном файле (`app_en.arb`)
   также есть `@`-аннотации с описаниями.

2. **`flutter gen-l10n`** — команда, которая читает `.arb` файлы и генерирует
   Dart-класс `AppLocalizations` с геттерами и методами для каждого ключа.

3. **Сгенерированный класс** подключается в `app.dart` через:
   - `AppLocalizations.localizationsDelegates` — список делегатов
   - `AppLocalizations.supportedLocales` — список языков

## Как использовать в коде

```dart
import 'package:kumbel_infrastructure/l10n/generated/app_localizations.dart';

// Простая строка (геттер):
final loc = AppLocalizations.of(context);
Text(loc.loginTitle);       // "Welcome" или "Добро пожаловать"

// Строка с параметром (метод):
Text(loc.greeting('Иван')); // "Hello, Иван!" или "Привет, Иван!"
```

## Как добавить новую строку

1. Откройте `lib/l10n/app_en.arb` и добавьте ключ + описание:
   ```json
   "newKey": "New string value",
   "@newKey": {
     "description": "Описание — для чего эта строка"
   }
   ```

2. Откройте `lib/l10n/app_ru.arb` и добавьте перевод:
   ```json
   "newKey": "Новая строка"
   ```

3. Выполните `flutter gen-l10n` (или `flutter run` — генерация запустится автоматически).

4. Используйте в коде: `AppLocalizations.of(context).newKey`

## Как добавить строку с параметром

В `.arb` файле используется синтаксис ICU (International Components for Unicode):

```json
"greeting": "Hello, {name}!",
"@greeting": {
  "description": "Приветствие с именем пользователя",
  "placeholders": {
    "name": {
      "type": "String",
      "example": "John"
    }
  }
}
```

В коде вызывается как метод: `loc.greeting('Иван')`

## Как добавить новый язык

1. Создайте файл `lib/l10n/app_xx.arb` (где `xx` — код языка, например `kk` для казахского).
2. Добавьте все ключи из `app_en.arb` с переводами.
3. Выполните `flutter gen-l10n`.
4. Готово! Новый язык автоматически добавится в `supportedLocales`.
