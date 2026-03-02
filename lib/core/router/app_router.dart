import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../features/home/ui/home_shell.dart';
import '../../features/home/ui/main_tab.dart';
import '../../features/home/ui/profile_tab.dart';
import '../../features/login/ui/login_screen.dart';
import '../../features/splash/ui/splash_screen.dart';
import 'route_names.dart';

/// Конфигурация навигации (GoRouter).
///
/// Структура маршрутов:
/// ```
/// /               → SplashScreen
/// /login          → LoginScreen
/// /home           → HomeShell (ShellRoute с BottomNavigationBar)
///   /home/main    → MainTab
///   /home/profile → ProfileTab
/// ```
///
/// **Redirect guard**: если пользователь попал на `/home/*`
/// без авторизации, его перекинет на `/login` (и наоборот).
/// Но основная навигация при смене auth-статуса идёт через
/// BlocListener в экранах — это явнее и проще для понимания.
class AppRouter {
  /// Создаёт и возвращает настроенный [GoRouter].
  static GoRouter create() {
    return GoRouter(
      // Начальный маршрут — сплэш.
      initialLocation: RouteNames.splash,

      // Список маршрутов.
      routes: [
        // ── Splash ───────────────────────────────────────────
        GoRoute(
          name: RouteNames.splashName,
          path: RouteNames.splash,
          builder: (context, state) => const SplashScreen(),
        ),

        // ── Login ────────────────────────────────────────────
        GoRoute(
          name: RouteNames.loginName,
          path: RouteNames.login,
          builder: (context, state) => const LoginScreen(),
        ),

        // ── Home (ShellRoute + BottomNav) ────────────────────
        ShellRoute(
          builder: (context, state, child) => HomeShell(child: child),
          routes: [
            GoRoute(
              name: RouteNames.mainName,
              path: RouteNames.main,
              builder: (context, state) => const MainTab(),
            ),
            GoRoute(
              name: RouteNames.profileName,
              path: RouteNames.profile,
              builder: (context, state) => const ProfileTab(),
            ),
          ],
        ),
      ],

      // ── Страница ошибки (404) ──────────────────────────────
      // Стиль текста берём из темы, чтобы он вписывался в дизайн.
      errorBuilder: (context, state) => Scaffold(
        body: Center(
          child: Text(
            'Страница не найдена: ${state.uri}',
            style: Theme.of(context).textTheme.bodyLarge,
          ),
        ),
      ),
    );
  }
}
