import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/router/route_names.dart';
import '../../../core/utils/logger.dart';
import '../../../data/repositories/auth_repository.dart';
import '../../../features/app/bloc/app_bloc.dart';
import '../../../features/app/bloc/app_state.dart';
import '../../../l10n/generated/app_localizations.dart';
import '../../../widgets/google_sign_in_button.dart';

/// Экран входа — показывает кнопку «Войти через Google».
///
/// Слушает [AppBloc] через [BlocListener]:
/// - Когда статус меняется на `authenticated` → переходим на Home.
/// - Это надёжнее, чем навигация внутри `onPressed`,
///   потому что BLoC гарантирует актуальный статус.
class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  /// Флаг загрузки — блокирует кнопку при нажатии.
  bool _isLoading = false;

  /// Обработчик нажатия на кнопку входа.
  Future<void> _onSignInPressed() async {
    setState(() => _isLoading = true);

    try {
      await AuthRepository.instance.signInWithGoogle();
      // Навигация произойдёт через BlocListener ниже.
    } catch (error) {
      AppLogger.error('LoginScreen: ошибка входа', error: error);

      if (!mounted) return;

      // Получаем локализованную строку ошибки.
      // AppLocalizations.of(context) — сгенерированный метод, возвращающий
      // объект со всеми строками из .arb файлов для текущего языка.
      final loc = AppLocalizations.of(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(loc.signInError),
        ),
      );
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    // Получаем объект локализации — содержит геттеры для всех строк.
    final loc = AppLocalizations.of(context);

    // Получаем текстовые стили из темы.
    // Никогда не используем AppTextStyles напрямую в виджетах —
    // только через Theme.of(context).textTheme, чтобы стили
    // автоматически адаптировались при смене темы.
    final textTheme = Theme.of(context).textTheme;

    return BlocListener<AppBloc, AppState>(
      // Слушаем только изменения статуса авторизации.
      listenWhen: (previous, current) => previous.status != current.status,
      listener: (context, state) {
        if (state.status == AppStatus.authenticated) {
          // Пользователь авторизовался → переходим на главную.
          context.go(RouteNames.main);
        }
      },
      child: Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: AppConstants.largePadding,
            ),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Заголовок.
                Text(
                  loc.loginTitle,
                  style: textTheme.headlineLarge,
                ),
                const SizedBox(height: AppConstants.smallPadding),

                // Подзаголовок.
                Text(
                  loc.loginSubtitle,
                  style: textTheme.bodySmall,
                ),
                const SizedBox(height: AppConstants.largePadding * 2),

                // Кнопка входа через Google.
                GoogleSignInButton(
                  onPressed: _onSignInPressed,
                  isLoading: _isLoading,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
