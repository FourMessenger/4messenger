import React from 'react';
import { X, Shield, Database, Eye, Lock, Globe, Clock, UserCheck, AlertTriangle, Mail } from 'lucide-react';

interface PrivacyPolicyProps {
  onClose: () => void;
  serverName?: string;
  language?: 'en' | 'ru';
}

const PrivacyPolicy: React.FC<PrivacyPolicyProps> = ({ onClose, serverName = '4 Messenger Server', language = 'en' }) => {
  const isRussian = language === 'ru';

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-2 sm:p-4">
      <div className="bg-gray-900 rounded-xl sm:rounded-2xl w-full max-w-4xl h-[95vh] sm:h-auto sm:max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-4 sm:p-6 border-b border-gray-700 flex items-center justify-between bg-gradient-to-r from-indigo-900/50 to-purple-900/50 shrink-0">
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <div className="w-10 h-10 sm:w-12 sm:h-12 bg-indigo-600 rounded-lg sm:rounded-xl flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 sm:w-6 sm:h-6 text-white" />
            </div>
            <div className="min-w-0">
              <h2 className="text-lg sm:text-xl font-bold text-white truncate">
                {isRussian ? 'Политика конфиденциальности' : 'Privacy Policy'}
              </h2>
              <p className="text-xs sm:text-sm text-gray-400 truncate">{serverName}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors shrink-0"
          >
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4 sm:space-y-6">
          {isRussian ? (
            <RussianPolicy serverName={serverName} />
          ) : (
            <EnglishPolicy serverName={serverName} />
          )}
        </div>

        {/* Footer */}
        <div className="p-3 sm:p-4 border-t border-gray-700 bg-gray-800/50 shrink-0">
          <p className="text-xs text-gray-500 text-center">
            {isRussian 
              ? `Последнее обновление: ${new Date().toLocaleDateString('ru-RU')}`
              : `Last updated: ${new Date().toLocaleDateString('en-US')}`
            }
          </p>
        </div>
      </div>
    </div>
  );
};

const EnglishPolicy: React.FC<{ serverName: string }> = ({ serverName }) => (
  <>
    <Section
      icon={<Eye className="w-5 h-5" />}
      title="1. Introduction"
    >
      <p>
        Welcome to {serverName}. This Privacy Policy explains how we collect, use, disclose, 
        and safeguard your information when you use our messaging service. Please read this 
        privacy policy carefully. By using the service, you agree to the collection and use 
        of information in accordance with this policy.
      </p>
    </Section>

    <Section
      icon={<Database className="w-5 h-5" />}
      title="2. Information We Collect"
    >
      <h4 className="font-semibold text-white mb-2">2.1 Account Information</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Username (required)</li>
        <li>Email address (required for account recovery)</li>
        <li>Password (stored securely using bcrypt encryption)</li>
        <li>Display name (optional)</li>
        <li>Profile picture/avatar (optional)</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">2.2 Messages and Content</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Text messages sent in chats, groups, and channels</li>
        <li>Files, images, videos, and voice messages you upload</li>
        <li>Poll responses and votes</li>
        <li>Message metadata (timestamps, read receipts)</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">2.3 Browser and Device Information</h4>
      <p className="mb-2">When you connect to the server, we automatically collect:</p>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>IP address</li>
        <li>Browser type and version (User-Agent)</li>
        <li>Operating system and platform</li>
        <li>Screen resolution and color depth</li>
        <li>Timezone and language preferences</li>
        <li>Device memory and CPU cores (hardware concurrency)</li>
        <li>Connection type (if available)</li>
        <li>Referrer URL</li>
        <li>Touch capability and other device features</li>
      </ul>
      <p className="text-yellow-400 text-sm">
        ⚠️ This information is collected for security purposes and to improve service quality.
      </p>

      <h4 className="font-semibold text-white mb-2 mt-4">2.4 Usage Data</h4>
      <ul className="list-disc list-inside space-y-1">
        <li>Login times and session duration</li>
        <li>Features used within the application</li>
        <li>Connection timestamps and frequency</li>
      </ul>
    </Section>

    <Section
      icon={<Lock className="w-5 h-5" />}
      title="3. How We Protect Your Data"
    >
      <h4 className="font-semibold text-white mb-2">3.1 Encryption</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Messages may be encrypted using AES-256-GCM encryption (when enabled by server administrator)</li>
        <li>Passwords are hashed using bcrypt with 12 rounds</li>
        <li>File uploads may be encrypted at rest</li>
        <li>All connections use HTTPS/WSS for transport security</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">3.2 Access Control</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Role-based access control (User, Moderator, Admin)</li>
        <li>JWT tokens for secure authentication</li>
        <li>Session management with automatic expiry</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">3.3 Data Storage</h4>
      <ul className="list-disc list-inside space-y-1">
        <li>Data is stored in SQLite database on the server</li>
        <li>Regular backups may be performed by the administrator</li>
        <li>Files are stored in a dedicated uploads directory</li>
      </ul>
    </Section>

    <Section
      icon={<Globe className="w-5 h-5" />}
      title="4. How We Use Your Information"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>To provide and maintain the messaging service</li>
        <li>To authenticate your identity and manage your account</li>
        <li>To deliver messages and notifications</li>
        <li>To enable voice and video calls between users</li>
        <li>To detect and prevent abuse, spam, and security threats</li>
        <li>To enforce our terms of service</li>
        <li>To improve service performance and user experience</li>
        <li>To send important service announcements</li>
        <li>To comply with legal obligations</li>
      </ul>
    </Section>

    <Section
      icon={<UserCheck className="w-5 h-5" />}
      title="5. Information Sharing"
    >
      <h4 className="font-semibold text-white mb-2">5.1 With Other Users</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Your username and display name are visible to other users</li>
        <li>Your profile picture is visible to users you interact with</li>
        <li>Messages you send are visible to chat participants</li>
        <li>Your online/offline status may be visible to others</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">5.2 With Administrators</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Server administrators can view user accounts and activity</li>
        <li>Administrators can access browser fingerprint data</li>
        <li>Moderators can view reports and take moderation actions</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">5.3 Legal Requirements</h4>
      <p>
        We may disclose your information if required by law or in response to valid requests 
        by public authorities (e.g., a court or government agency).
      </p>
    </Section>

    <Section
      icon={<Clock className="w-5 h-5" />}
      title="6. Data Retention"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>Account data is retained until you delete your account</li>
        <li>Messages are retained indefinitely unless deleted by users or administrators</li>
        <li>Browser fingerprint data may be retained for security analysis</li>
        <li>Log data may be retained for up to 90 days</li>
        <li>Deleted content may persist in backups for a limited time</li>
      </ul>
    </Section>

    <Section
      icon={<Shield className="w-5 h-5" />}
      title="7. Your Rights"
    >
      <p className="mb-2">You have the right to:</p>
      <ul className="list-disc list-inside space-y-1">
        <li>Access your personal data</li>
        <li>Correct inaccurate personal data</li>
        <li>Delete your account and associated data</li>
        <li>Export your data (where technically feasible)</li>
        <li>Object to processing of your data</li>
        <li>Withdraw consent at any time</li>
      </ul>
      <p className="mt-4 text-sm text-gray-400">
        To exercise these rights, please contact the server administrator.
      </p>
    </Section>

    <Section
      icon={<Mail className="w-5 h-5" />}
      title="8. Email Communications"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>Email verification may be required for registration</li>
        <li>Password reset emails will be sent when requested</li>
        <li>Important security notifications may be sent to your email</li>
      </ul>
    </Section>

    <Section
      icon={<AlertTriangle className="w-5 h-5" />}
      title="9. Third-Party Services"
    >
      <h4 className="font-semibold text-white mb-2">9.1 CAPTCHA Verification</h4>
      <p className="mb-4">
        We use Cloudflare Turnstile for CAPTCHA verification. When completing a CAPTCHA challenge, 
        Cloudflare may collect certain information in accordance with their privacy policy.
      </p>

      <h4 className="font-semibold text-white mb-2">9.2 STUN Servers (Voice/Video Calls)</h4>
      <p className="mb-4">
        For peer-to-peer calls, we use public STUN servers (including Google's) to establish 
        connections. These servers may receive your IP address during call setup.
      </p>

      <h4 className="font-semibold text-white mb-2">9.3 YouTube Embeds</h4>
      <p>
        When viewing YouTube videos shared in chats, you are subject to YouTube's privacy policy. 
        YouTube may collect information about your viewing habits.
      </p>
    </Section>

    <Section
      icon={<Lock className="w-5 h-5" />}
      title="10. Security Measures"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>CAPTCHA protection against automated attacks</li>
        <li>Server password protection (if enabled)</li>
        <li>Rate limiting on API endpoints</li>
        <li>Secure WebSocket connections</li>
        <li>Helmet.js security headers</li>
        <li>Role-based access control</li>
        <li>Maintenance mode for emergency situations</li>
      </ul>
    </Section>

    <Section
      icon={<AlertTriangle className="w-5 h-5" />}
      title="11. Children's Privacy"
    >
      <p>
        This service is not intended for children under the age of 13. We do not knowingly 
        collect personal information from children under 13. If you are a parent or guardian 
        and believe your child has provided us with personal information, please contact 
        the server administrator.
      </p>
    </Section>

    <Section
      icon={<Globe className="w-5 h-5" />}
      title="12. Changes to This Policy"
    >
      <p>
        We may update this Privacy Policy from time to time. We will notify you of any changes 
        by posting the new Privacy Policy on this page and updating the "Last updated" date. 
        You are advised to review this Privacy Policy periodically for any changes.
      </p>
    </Section>

    <Section
      icon={<Mail className="w-5 h-5" />}
      title="13. Contact Information"
    >
      <p>
        If you have any questions about this Privacy Policy, please contact the server 
        administrator through the messaging platform or via email if provided.
      </p>
    </Section>

    <div className="mt-8 p-4 bg-indigo-900/30 rounded-lg border border-indigo-700">
      <p className="text-center text-gray-300">
        By using this service, you acknowledge that you have read and understood this 
        Privacy Policy and agree to be bound by its terms.
      </p>
    </div>
  </>
);

const RussianPolicy: React.FC<{ serverName: string }> = ({ serverName }) => (
  <>
    <Section
      icon={<Eye className="w-5 h-5" />}
      title="1. Введение"
    >
      <p>
        Добро пожаловать на {serverName}. Эта Политика конфиденциальности объясняет, как мы собираем, 
        используем, раскрываем и защищаем вашу информацию при использовании нашего сервиса обмена 
        сообщениями. Пожалуйста, внимательно прочитайте эту политику конфиденциальности. Используя 
        сервис, вы соглашаетесь на сбор и использование информации в соответствии с этой политикой.
      </p>
    </Section>

    <Section
      icon={<Database className="w-5 h-5" />}
      title="2. Информация, которую мы собираем"
    >
      <h4 className="font-semibold text-white mb-2">2.1 Данные аккаунта</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Имя пользователя (обязательно)</li>
        <li>Адрес электронной почты (обязательно для восстановления аккаунта)</li>
        <li>Пароль (хранится в зашифрованном виде с использованием bcrypt)</li>
        <li>Отображаемое имя (необязательно)</li>
        <li>Фотография профиля/аватар (необязательно)</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">2.2 Сообщения и контент</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Текстовые сообщения в чатах, группах и каналах</li>
        <li>Файлы, изображения, видео и голосовые сообщения</li>
        <li>Ответы и голоса в опросах</li>
        <li>Метаданные сообщений (время отправки, статус прочтения)</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">2.3 Данные браузера и устройства</h4>
      <p className="mb-2">При подключении к серверу мы автоматически собираем:</p>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>IP-адрес</li>
        <li>Тип и версия браузера (User-Agent)</li>
        <li>Операционная система и платформа</li>
        <li>Разрешение экрана и глубина цвета</li>
        <li>Часовой пояс и языковые настройки</li>
        <li>Объем памяти устройства и количество ядер процессора</li>
        <li>Тип подключения (если доступно)</li>
        <li>URL источника перехода</li>
        <li>Поддержка сенсорного ввода и другие характеристики устройства</li>
      </ul>
      <p className="text-yellow-400 text-sm">
        ⚠️ Эта информация собирается в целях безопасности и для улучшения качества обслуживания.
      </p>

      <h4 className="font-semibold text-white mb-2 mt-4">2.4 Данные об использовании</h4>
      <ul className="list-disc list-inside space-y-1">
        <li>Время входа и продолжительность сессий</li>
        <li>Используемые функции приложения</li>
        <li>Временные метки и частота подключений</li>
      </ul>
    </Section>

    <Section
      icon={<Lock className="w-5 h-5" />}
      title="3. Как мы защищаем ваши данные"
    >
      <h4 className="font-semibold text-white mb-2">3.1 Шифрование</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Сообщения могут быть зашифрованы с использованием AES-256-GCM (если включено администратором)</li>
        <li>Пароли хешируются с использованием bcrypt с 12 раундами</li>
        <li>Загруженные файлы могут быть зашифрованы при хранении</li>
        <li>Все соединения используют HTTPS/WSS для защиты передачи данных</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">3.2 Контроль доступа</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Ролевой контроль доступа (Пользователь, Модератор, Администратор)</li>
        <li>JWT-токены для безопасной аутентификации</li>
        <li>Управление сессиями с автоматическим истечением срока действия</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">3.3 Хранение данных</h4>
      <ul className="list-disc list-inside space-y-1">
        <li>Данные хранятся в базе данных SQLite на сервере</li>
        <li>Регулярное резервное копирование может выполняться администратором</li>
        <li>Файлы хранятся в специальной директории загрузок</li>
      </ul>
    </Section>

    <Section
      icon={<Globe className="w-5 h-5" />}
      title="4. Как мы используем вашу информацию"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>Для предоставления и поддержки сервиса обмена сообщениями</li>
        <li>Для аутентификации и управления вашим аккаунтом</li>
        <li>Для доставки сообщений и уведомлений</li>
        <li>Для обеспечения голосовых и видеозвонков</li>
        <li>Для обнаружения и предотвращения злоупотреблений, спама и угроз безопасности</li>
        <li>Для соблюдения условий использования</li>
        <li>Для улучшения производительности и пользовательского опыта</li>
        <li>Для отправки важных сервисных объявлений</li>
        <li>Для соблюдения требований законодательства</li>
      </ul>
    </Section>

    <Section
      icon={<UserCheck className="w-5 h-5" />}
      title="5. Передача информации"
    >
      <h4 className="font-semibold text-white mb-2">5.1 Другим пользователям</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Ваше имя пользователя и отображаемое имя видны другим пользователям</li>
        <li>Ваше фото профиля видно пользователям, с которыми вы взаимодействуете</li>
        <li>Сообщения видны участникам чата</li>
        <li>Ваш статус онлайн/офлайн может быть виден другим</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">5.2 Администраторам</h4>
      <ul className="list-disc list-inside space-y-1 mb-4">
        <li>Администраторы сервера могут просматривать аккаунты и активность пользователей</li>
        <li>Администраторы имеют доступ к данным цифрового отпечатка браузера</li>
        <li>Модераторы могут просматривать жалобы и предпринимать действия по модерации</li>
      </ul>

      <h4 className="font-semibold text-white mb-2">5.3 Требования законодательства</h4>
      <p>
        Мы можем раскрыть вашу информацию, если это требуется по закону или в ответ на 
        действительные запросы государственных органов.
      </p>
    </Section>

    <Section
      icon={<Clock className="w-5 h-5" />}
      title="6. Срок хранения данных"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>Данные аккаунта хранятся до удаления вашего аккаунта</li>
        <li>Сообщения хранятся бессрочно, если не удалены пользователями или администраторами</li>
        <li>Данные цифрового отпечатка браузера могут храниться для анализа безопасности</li>
        <li>Данные журналов могут храниться до 90 дней</li>
        <li>Удаленный контент может сохраняться в резервных копиях ограниченное время</li>
      </ul>
    </Section>

    <Section
      icon={<Shield className="w-5 h-5" />}
      title="7. Ваши права"
    >
      <p className="mb-2">Вы имеете право:</p>
      <ul className="list-disc list-inside space-y-1">
        <li>Получить доступ к вашим персональным данным</li>
        <li>Исправить неточные персональные данные</li>
        <li>Удалить ваш аккаунт и связанные данные</li>
        <li>Экспортировать ваши данные (где технически возможно)</li>
        <li>Возражать против обработки ваших данных</li>
        <li>Отозвать согласие в любое время</li>
      </ul>
      <p className="mt-4 text-sm text-gray-400">
        Для реализации этих прав обратитесь к администратору сервера.
      </p>
    </Section>

    <Section
      icon={<Mail className="w-5 h-5" />}
      title="8. Электронные коммуникации"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>Для регистрации может потребоваться подтверждение email</li>
        <li>Письма для сброса пароля отправляются по запросу</li>
        <li>Важные уведомления безопасности могут отправляться на вашу почту</li>
      </ul>
    </Section>

    <Section
      icon={<AlertTriangle className="w-5 h-5" />}
      title="9. Сторонние сервисы"
    >
      <h4 className="font-semibold text-white mb-2">9.1 Проверка CAPTCHA</h4>
      <p className="mb-4">
        Мы используем Cloudflare Turnstile для проверки CAPTCHA. При прохождении проверки 
        Cloudflare может собирать определенную информацию в соответствии со своей политикой 
        конфиденциальности.
      </p>

      <h4 className="font-semibold text-white mb-2">9.2 STUN-серверы (голосовые/видеозвонки)</h4>
      <p className="mb-4">
        Для peer-to-peer звонков мы используем публичные STUN-серверы (включая серверы Google) 
        для установления соединений. Эти серверы могут получать ваш IP-адрес при настройке звонка.
      </p>

      <h4 className="font-semibold text-white mb-2">9.3 Встраивание YouTube</h4>
      <p>
        При просмотре видео YouTube, размещенных в чатах, вы подпадаете под действие политики 
        конфиденциальности YouTube. YouTube может собирать информацию о ваших предпочтениях просмотра.
      </p>
    </Section>

    <Section
      icon={<Lock className="w-5 h-5" />}
      title="10. Меры безопасности"
    >
      <ul className="list-disc list-inside space-y-1">
        <li>Защита CAPTCHA от автоматизированных атак</li>
        <li>Защита паролем сервера (если включено)</li>
        <li>Ограничение частоты запросов к API</li>
        <li>Безопасные WebSocket-соединения</li>
        <li>Заголовки безопасности Helmet.js</li>
        <li>Ролевой контроль доступа</li>
        <li>Режим обслуживания для экстренных ситуаций</li>
      </ul>
    </Section>

    <Section
      icon={<AlertTriangle className="w-5 h-5" />}
      title="11. Конфиденциальность детей"
    >
      <p>
        Этот сервис не предназначен для детей младше 13 лет. Мы сознательно не собираем 
        персональную информацию от детей младше 13 лет. Если вы являетесь родителем или 
        опекуном и считаете, что ваш ребенок предоставил нам персональную информацию, 
        пожалуйста, свяжитесь с администратором сервера.
      </p>
    </Section>

    <Section
      icon={<Globe className="w-5 h-5" />}
      title="12. Изменения в политике"
    >
      <p>
        Мы можем время от времени обновлять эту Политику конфиденциальности. Мы уведомим вас 
        о любых изменениях, разместив новую Политику конфиденциальности на этой странице и 
        обновив дату «Последнее обновление». Рекомендуем периодически просматривать эту 
        Политику конфиденциальности на предмет изменений.
      </p>
    </Section>

    <Section
      icon={<Mail className="w-5 h-5" />}
      title="13. Контактная информация"
    >
      <p>
        Если у вас есть вопросы по этой Политике конфиденциальности, пожалуйста, свяжитесь 
        с администратором сервера через платформу обмена сообщениями или по электронной почте, 
        если она указана.
      </p>
    </Section>

    <div className="mt-8 p-4 bg-indigo-900/30 rounded-lg border border-indigo-700">
      <p className="text-center text-gray-300">
        Используя этот сервис, вы подтверждаете, что прочитали и поняли эту Политику 
        конфиденциальности и соглашаетесь соблюдать её условия.
      </p>
    </div>
  </>
);

const Section: React.FC<{ icon: React.ReactNode; title: string; children: React.ReactNode }> = ({ 
  icon, 
  title, 
  children 
}) => (
  <div className="space-y-2 sm:space-y-3">
    <div className="flex items-center gap-2">
      <div className="text-indigo-400 shrink-0">{icon}</div>
      <h3 className="text-base sm:text-lg font-semibold text-white">{title}</h3>
    </div>
    <div className="text-sm sm:text-base text-gray-300 pl-6 sm:pl-7 space-y-2">
      {children}
    </div>
  </div>
);

export default PrivacyPolicy;
