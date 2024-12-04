```markdown
# Описание проекта

Этот проект представляет собой простой сервер на языке Go, реализующий механизм работы с **access token** и **refresh token** для аутентификации и авторизации пользователей. Основные возможности:
- Генерация **access token** (временного токена для доступа к ресурсам).
- Генерация и хранение **refresh token** (для обновления access token).
- Проверка токенов и обновление **access token** с использованием **refresh token**.

Сервер будет доступен по адресу [http://localhost:8080](http://localhost:8080).

## Ограничения

- Данные (включая `refresh token`) не сохраняются между перезапусками сервера, так как база данных отсутствует.
- Этот проект предназначен для учебных целей и демонстрации работы с токенами.
