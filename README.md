## Traceroute - для определения маршрутов следования данных в сетях TCP/IP
Учебный проект Коловериной Алены по курсу Python.

## 1. Цель проекта

Цель проекта - Написать скрипт, который выводит маршрут (traceroute) и номера автономных систем промежуточных узлов, используя ответы службы whois региональных регистраторов.


## 2. Стек технологий

Для реализации системы предлагается следующий стек технологий:

* Язык Python
* Библиотека prettytable для реализации вывода в таблицу


## 3. Реализованные требования

* Поддержка ipV4,ipV6
* Вывод таблицы трассировки с временем ответа 
* Отправка N запросов (по умолчанию 3)
* Задание интервала времени между запрсами
* Задание таймаута ожидания
* Задание максимального TTL
* Указание промежуточных ip

## 4. Инструкция запуска
1) Перейти в директории
2) запустить (sudo python3) trace.py (ip или DNS-имя)

## 5. Примеры запуска
![пример](/var/folders/x4/3070zn7x2m5dk990wy2g8rv00000gn/T/TemporaryItems/NSIRD_screencaptureui_FphX6T/Снимок экрана 2024-05-08 в 20.20.12.png)
![пример](/var/folders/x4/3070zn7x2m5dk990wy2g8rv00000gn/T/TemporaryItems/NSIRD_screencaptureui_Z20hMh/Снимок экрана 2024-05-08 в 20.19.37.png)