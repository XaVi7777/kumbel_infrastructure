import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/router/route_names.dart';
import '../../../features/app/bloc/app_bloc.dart';
import '../../../features/app/bloc/app_event.dart';
import '../../../features/app/bloc/app_state.dart';
import '../../../l10n/generated/app_localizations.dart';
import '../../../ui_kit/ui_kit.dart';
import '../../../widgets/user_avatar.dart';

/// Вкладка «Профиль» — информация о пользователе + кнопка выхода.
///
/// При нажатии «Выйти»:
/// 1. Отправляем [AppSignOutRequested] в BLoC.
/// 2. BLoC вызывает `authRepository.signOut()`.
/// 3. Стрим `authStateChanges` присылает `UserModel.empty`.
/// 4. BLoC эмитит `AppState.unauthenticated()`.
/// 5. BlocListener (здесь) ловит смену статуса и делает `context.go('/login')`.
class ProfileTab extends StatelessWidget {
  const ProfileTab({super.key});

  @override
  Widget build(BuildContext context) {
    // Получаем объект локализации — типобезопасный доступ к строкам.
    final loc = AppLocalizations.of(context);
    final appState = context.watch<AppBloc>().state;
    final user = appState.user;

    // Текстовые стили берём из темы, а не напрямую из AppTextStyles.
    // Это позволяет автоматически адаптироваться к светлой/тёмной теме.
    final textTheme = Theme.of(context).textTheme;

    return BlocListener<AppBloc, AppState>(
      listenWhen: (previous, current) => previous.status != current.status,
      listener: (context, state) {
        if (state.status == AppStatus.unauthenticated) {
          context.go(RouteNames.login);
        }
      },
      child: Scaffold(
        appBar: AppBar(
          title: Text(loc.profileTitle),
        ),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(AppConstants.largePadding),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Аватар — переиспользуемый виджет UserAvatar.
                // Вместо дублирования CircleAvatar на каждом экране
                // используем единый компонент из lib/widgets/.
                UserAvatar(photoUrl: user.photoUrl),
                const SizedBox(height: AppConstants.largePadding),

                // Имя.
                Text(
                  user.displayName,
                  style: textTheme.headlineMedium,
                ),
                const SizedBox(height: AppConstants.smallPadding),

                // Email.
                Text(
                  user.email,
                  style: textTheme.bodySmall,
                ),
                const SizedBox(height: AppConstants.largePadding * 2),

                // Кнопка «Выйти».
                AppButton(
                  text: loc.signOut,
                  onPressed: () {
                    context.read<AppBloc>().add(const AppSignOutRequested());
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
