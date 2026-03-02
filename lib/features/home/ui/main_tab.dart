import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import '../../../core/constants/app_constants.dart';
import '../../../features/app/bloc/app_bloc.dart';
import '../../../l10n/generated/app_localizations.dart';
import '../../../widgets/user_avatar.dart';

/// Вкладка «Главная» — приветствие с именем и аватаром пользователя.
///
/// Читает данные из [AppBloc] через `context.watch`.
class MainTab extends StatelessWidget {
  const MainTab({super.key});

  @override
  Widget build(BuildContext context) {
    // Получаем объект локализации — содержит геттеры и методы для строк.
    // Для строк без параметров — геттеры (loc.tabMain).
    // Для строк с параметрами — методы (loc.greeting(name)).
    final loc = AppLocalizations.of(context);
    final appState = context.watch<AppBloc>().state;
    final user = appState.user;

    // Получаем текстовые стили из темы — это правильный подход.
    // Стили определены в AppTheme.light → textTheme, а виджеты
    // обращаются к ним через Theme.of(context).textTheme.
    final textTheme = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(
        title: Text(loc.tabMain),
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(AppConstants.largePadding),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Аватар пользователя — переиспользуемый виджет.
              // Раньше тут был дублированный код CircleAvatar,
              // теперь используем UserAvatar (lib/widgets/user_avatar.dart).
              UserAvatar(photoUrl: user.photoUrl),
              const SizedBox(height: AppConstants.largePadding),

              // Приветствие с именем.
              // Раньше: loc.translateWithArgs('greeting', {'name': ...})
              // Теперь: loc.greeting(name) — типобезопасный метод,
              // сгенерированный из .arb файла (ключ "greeting" с плейсхолдером {name}).
              Text(
                loc.greeting(
                  user.displayName.isNotEmpty ? user.displayName : 'User',
                ),
                style: textTheme.headlineMedium,
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
