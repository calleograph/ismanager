# Лицензии компонентов

Apache License 2.0 распространяется на исходный код IS Manager. Использованные внешние компоненты сохраняют собственные лицензии. Полный текст Apache-2.0 и уведомления входят в корень репозитория. [LICENSE](../LICENSE) · [NOTICE](../NOTICE)

| Компонент | Условия и назначение |
| --- | --- |
| MFA Gate | Apache-2.0, адаптированные элементы LDAP, тестового стенда и темы |
| Flask, Werkzeug, Jinja, Click | BSD-3-Clause, серверный интерфейс |
| Gunicorn | MIT, сервер WSGI |
| smbprotocol и pyspnego | Клиент SMB2/3 и аутентификация доменной учётной записи, MIT. [smbprotocol](https://pypi.org/project/smbprotocol/1.17.0/) · [pyspnego](https://github.com/jborean93/pyspnego) |
| ldap3 | LGPL-3.0, отдельная установленная библиотека LDAP |
| cryptography | Apache-2.0 или BSD-3-Clause, шифрование секретов и сертификаты |
| PyOTP | MIT, TOTP |
| Inter, Manrope | SIL Open Font License 1.1, шрифты включены вместе с OFL |
| Lucide | ISC и уведомления исходных наборов, локальный SVG-спрайт с приложенной лицензией |
| Slovnet, Navec, Natasha, Razdel | MIT, локальное распознавание именованных сущностей |
| pymorphy3 и русские словари OpenCorpora | Код библиотеки MIT, данные словаря CC BY-SA 3.0, морфология |
| FFmpeg, Poppler, Tesseract, Antiword, Catdoc | Системные пакеты Debian с собственными лицензиями в образе, используются через отдельные процессы |
| python-calamine, striprtf, chardet, olefile | Чтение бинарных книг Excel, RTF и определение кодировки. [python-calamine · MIT](https://pypi.org/project/python-calamine/0.9.1/) · [striprtf · BSD-3-Clause](https://pypi.org/project/striprtf/0.0.35/) · [chardet · 0BSD](https://pypi.org/project/chardet/7.7.0/) · [olefile и лицензия](https://pypi.org/project/olefile/0.47/) |
| python-docx, openpyxl, Pillow, defusedxml | Обработка документов и изображений. Пакеты установлены со своими файлами лицензий |
| GigaAM v3, Silero VAD, PyTorch, TorchAudio, ONNX Runtime | Зависимости выделенного обработчика речи. Веса GigaAM загружаются отдельно от исходников |

Проект публикует исходный код и рецепты сборки. При распространении готового образа сохраняйте лицензии и уведомления установленных пакетов, соблюдайте условия соответствующих дистрибутивов для их бинарных компонентов. Справочники, клиентские документы и настройки конкретной организации не следует смешивать с публичной поставкой.

[Лицензии для речи и веса модели](TRANSCRIPTION.md) · [Словари OpenCorpora](https://opencorpora.org/dict.php) · [MFA Gate](https://github.com/calleograph/mfa-gate) · [Шрифты](../app/static/fonts/OFL.txt) · [Иконки](../app/static/icons/LICENSE-lucide.txt)
