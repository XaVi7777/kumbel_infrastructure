import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/router/route_names.dart';
import '../../../data/repositories/auth_repository.dart';
import '../../../l10n/generated/app_localizations.dart';
import '../../../ui_kit/ui_kit.dart';

/// Сплэш-экран — первый экран при запуске приложения.
///
/// Что происходит:
/// 1. Показываем название приложения + индикатор загрузки.
/// 2. Ждём [AppConstants.splashDelaySeconds] секунд.
/// 3. Проверяем, авторизован ли пользователь.
/// 4. Переходим на Home (если авторизован) или Login (если нет).
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    _navigateAfterDelay();
  }

  /// Ждём, проверяем авторизацию и переходим.
  Future<void> _navigateAfterDelay() async {
    // Ждём заданное время (имитация загрузки / анимация).
    await Future.delayed(
      Duration(seconds: AppConstants.splashDelaySeconds),
    );

    // Проверяем, что виджет ещё «живой» (экран не был закрыт).
    if (!mounted) return;

    // Проверяем статус авторизации.
    final bool isLoggedIn = AuthRepository.instance.isLoggedIn;

    if (isLoggedIn) {
      context.go(RouteNames.main);
    } else {
      context.go(RouteNames.login);
    }
  }

  @override
  Widget build(BuildContext context) {
    // Получаем экземпляр локализации из контекста.
    // Используем `AppLocalizations.of(context)` — это сгенерированный метод,
    // который возвращает объект с геттерами для каждой строки из .arb файлов.
    final loc = AppLocalizations.of(context);

    // Получаем текстовые стили из темы приложения.
    // Это правильный подход: стили определены в AppTheme, а виджеты
    // берут их через Theme.of(context).textTheme — так при смене темы
    // (например, на тёмную) все тексты автоматически обновятся.
    final textTheme = Theme.of(context).textTheme;

    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Название приложения.
            // Вместо loc.translate('appName') теперь просто loc.appName.
            Text(
              loc.appName,
              style: textTheme.headlineLarge,
            ),
            const SizedBox(height: AppConstants.largePadding),

            // Индикатор загрузки.
            const AppLoadingIndicator(),
            const SizedBox(height: AppConstants.defaultPadding),

            // Текст «Загрузка...».
            Text(
              loc.splashLoading,
              style: textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}
