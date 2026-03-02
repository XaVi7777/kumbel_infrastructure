import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';

import 'core/utils/logger.dart';
import 'features/app/ui/app.dart';

/// Точка входа в приложение.
///
/// Порядок инициализации:
/// 1. Говорим Flutter, что будем вызывать async-код до `runApp`.
/// 2. Загружаем переменные окружения из `.env` файла.
/// 3. Инициализируем Firebase.
/// 4. Запускаем приложение.
void main() async {
  // Обязательно вызываем перед любыми async-операциями.
  WidgetsFlutterBinding.ensureInitialized();

  // Загружаем .env (если файла нет — не падаем, просто логируем).
  try {
    await dotenv.load();
    AppLogger.info('main: .env загружен');
  } catch (_) {
    AppLogger.warning('main: .env файл не найден — используем значения по умолчанию');
  }

  // Инициализируем Firebase.
  await Firebase.initializeApp();
  AppLogger.info('main: Firebase инициализирован');

  // Запускаем приложение.
  runApp(const App());
}
