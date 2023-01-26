# Dedecmd_bruteforce


## Установка

Для работы скрипта требуется установить необходимые библиотеки:

```
sudo apt install img2pdf
sudo apt install python3-pip

pip install lxml / pip3 install lxml
pip install requests / pip3 install requests
pip install Pillow / pip3 install Pillow
pip install beautifulsoup4 / pip3 install beautifulsoup4

(Может потребоваться sudo)
```

В директории со скриптом:

```
git clone https://github.com/anycaptcha/anycaptcha-python
cd anycaptcha-python

sudo chmod +x setup.py

pip install -e .

(Может потребоваться sudo)
```

---

## Файлы для работы скрипта

В текущей директории скрипта должны располагаться следующие файлы:

* servers.txt - файл с названиямми серверов
  
```
https://www.domain.com
https://20.12.53.20
...
```

* usernames.txt - файл с именами пользователей

```
test
admin
something
letmein
...
```

* passwords.txt - файл с паролями

```
something
wordlist
admin
generator
...
```

* proxy.txt - файл содержит порты для proxy(ip и протокол определены статично. При изменении их, нужно изменить соответствующие значения в коде.)

```
20341
32032
33244
...
```

**Во всех файлах не должно быть пустых строк в конце!!**

---

## Использование скрипта

```
sudo ./dede_brute.sh
```
