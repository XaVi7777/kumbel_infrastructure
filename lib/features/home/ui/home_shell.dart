import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';
import '../../../l10n/generated/app_localizations.dart';

/// Оболочка (Shell) для домашних вкладок.
///
/// Используется с [ShellRoute] из GoRouter.
/// [ShellRoute] оборачивает дочерние роуты в общий layout —
/// в нашем случае это [Scaffold] с [BottomNavigationBar].
///
/// [child] — это текущий экран вкладки (MainTab или ProfileTab),
/// который GoRouter подставляет автоматически.
class HomeShell extends StatelessWidget {
  /// Текущий дочерний виджет (вкладка).
  final Widget child;

  const HomeShell({super.key, required this.child});

  /// Определяем текущий индекс вкладки по URL.
  int _currentIndex(BuildContext context) {
    final String location = GoRouterState.of(context).uri.path;
    if (location.startsWith('/home/profile')) {
      return AppConstants.profileTabIndex;
    }
    return AppConstants.mainTabIndex;
  }

  /// Обработчик переключения вкладок.
  void _onTabTapped(BuildContext context, int index) {
    switch (index) {
      case AppConstants.mainTabIndex:
        context.go('/home/main');
        break;
      case AppConstants.profileTabIndex:
        context.go('/home/profile');
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    // Получаем объект локализации для доступа к переведённым строкам.
    // Теперь строки доступны как геттеры: loc.tabMain, loc.tabProfile и т.д.
    final loc = AppLocalizations.of(context);
    final int selectedIndex = _currentIndex(context);

    return Scaffold(
      // Тело — текущая вкладка.
      body: child,

      // Нижняя навигация.
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: selectedIndex,
        onTap: (index) => _onTabTapped(context, index),
        items: [
          BottomNavigationBarItem(
            icon: const Icon(Icons.home_outlined),
            activeIcon: const Icon(Icons.home),
            label: loc.tabMain,
          ),
          BottomNavigationBarItem(
            icon: const Icon(Icons.person_outline),
            activeIcon: const Icon(Icons.person),
            label: loc.tabProfile,
          ),
        ],
      ),
    );
  }
}
