
# Lambda CTF 2019

Райтап к прошедшему 10 ноября 2019 Lambda CTF

## Forensics

В разделе форенсики нас ждали 3 таска на самые разные тематики

### Уличный контейнер

> Сможете проанализировать этот контейнер с данными? <br>
> [[taskf_for1](/files/task_for1?raw=true)]

Дан некий файл `task_for1`. Первое что делаем с неизвестными файлами, проверяем формат утилитой `file`

```no-highligh
$ file task_for1
/home/user/task_for1: Zip archive data, at least v2.0 to extract
```

Имеет zip-архив. Смотрим содержимое:

```no-highligh
$ zipinfo task_for1
Archive: /home/user/task_for1
Zip file size: 6275431 bytes, number of entries: 3
-rw-r--r-- 2.1 unx 10240 bX defN 19-Oct-09 14:15 some
drwxrwxr-x 2.1 unx 0 bx stor 19-Oct-09 14:15 __MACOSX/
-rw-r--r-- 2.1 unx 176 bX defN 19-Oct-09 14:15 __MACOSX/._some
3 files, 10416 bytes uncompressed, 10337 bytes compressed: 0.8%
```

Видим что процент компрессии соверешнно неадекватный, размер содержимого сильно меньше чем размер самого архива. Делаем вывод, что файл содержит нечто большее чем просто архив. Значит пришло время утилиты `binwalk`

```no-highligh
$ binwalk task_for1

DECIMAL HEXADECIMAL DESCRIPTION
--------------------------------------------------------------------------------
0 0x0 Zip archive data, at least v2.0 to extract, name: some
10311 0x2847 Zip archive data, at least v1.0 to extract, name: __MACOSX/
10366 0x287E Zip archive data, at least v2.0 to extract, name: __MACOSX/._some
10737 0x29F1 End of Zip archive, footer length: 22
10759 0x2A07 PNG image, 1941 x 1490, 8-bit/color RGBA, non-interlaced
```

Найдено png-изображение. Отрезаем его и смотрим

```no-highligh
$ dd skip=10759 if=task_for1 of=some_image.png bs=1
```

![hidden image](/files/some_image.png?raw=true)

А вот и флаг!

![hidden image part](/files/some_image_part.png?raw=true)

Флаг: `flag{a63bedadc546b84a38cbe6f0329d6f2e}`

### Бесплатный флаг

> Мы хотели просто так отдать вам флаг, но у нас есть только архив, а пароль мы забыли. <br>
> [[for2.zip](/files/for2.zip?raw=true)]

Дан запароленный архив. Первое что приходит в голову - перебрать пароли по словарю. Воспользуемся утилитой `JohnTheRipper` со словарем **rockyou**. Для этого извлечем необходимые для `JohnTheRipper` данные с помощью утилиты `zip2john` идущей в комплекте

```no-highligh
$ zip2john for2.zip > for2.zip.hashes
for2.zip/dev/ is not encrypted!
ver 1.0 for2.zip/dev/ is not encrypted, or stored with non-handled compression type
ver 1.0 efh 5455 efh 7875 for2.zip/dev/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=50, decmplen=38, crc=8561BABE
```

Теперь запускаем сам `john`

```no-highligh
$ john --wordlist=rockyou.txt for2.zip.hashes
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 36 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rabbit (for2.zip/dev/flag.txt)
1g 0:00:00:00 DONE (2019-11-12 16:33) 14.28g/s 1053Kp/s 1053Kc/s 1053KC/s 123456..college07
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Смотрим результат

```no-highligh
$ john --show for2.zip.hashes
for2.zip/dev/flag.txt:rabbit:dev/flag.txt:for2.zip::for2.zip
  
1 password hash cracked, 0 left
```

Пароль **rabbit**.

```no-highligh
$ unzip for2.zip
Archive: for2.zip
creating: dev/
[for2.zip] dev/flag.txt password:
extracting: dev/flag.txt
$ cat dev/flag.txt
flag{58873c1d758805c086232436dd092017}
```

Флаг: `flag{58873c1d758805c086232436dd092017}`

### Хайповая Клава

> Пришёл я в магазин с USB-клавиатурой, а она мне как раз! <br>
> [[for3.pcapng](/files/for3.pcapng?raw=true)]

Дан файл for3.pcapng. Pcap-ng представляет собой дамп пакетов, переданных по некоторому каналу. Открываем ее утилитой Wireshark. И первое что бросается в глаза - протокол USB:

![wireshark screenshot](/files/keyb_scr1.png?raw=true)

Разбираться в протоколе долго и лениво, загуглим. Находим два разбора ([раз](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4) и [два](https://bitvijays.github.io/LFC-Forensics.html)) подобного таска. Обращаем внимание, где заложеная информация о нажатой клавише. Также замечаем, что данные от источника 1.2.1 не подходят не по размеру данных, ни по содержимому. Делаем предположение, что 1.2.1 не является клавиатурой, вместо этого рассматриваем более подходящие пакеты от 1.1.1

![wireshark screenshot 2](/files/keyb_scr2.png?raw=true)

Экспортируем отфильтрованные пакеты, не забыв добавить колонку Leftover Capture Data

![wireshark screenshot 3](/files/keyb_scr3.png?raw=true)

Пишем скрипт (я вновь воспользуюсь python 2.7), подглядывая в обе статьи:

```python
import csv

usb_codes = {
   0x04:"aA", 0x05:"bB", 0x06:"cC", 0x07:"dD", 0x08:"eE", 0x09:"fF",
   0x0A:"gG", 0x0B:"hH", 0x0C:"iI", 0x0D:"jJ", 0x0E:"kK", 0x0F:"lL",
   0x10:"mM", 0x11:"nN", 0x12:"oO", 0x13:"pP", 0x14:"qQ", 0x15:"rR",
   0x16:"sS", 0x17:"tT", 0x18:"uU", 0x19:"vV", 0x1A:"wW", 0x1B:"xX",
   0x1C:"yY", 0x1D:"zZ", 0x1E:"1!", 0x1F:"2@", 0x20:"3#", 0x21:"4$",
   0x22:"5%", 0x23:"6^", 0x24:"7&", 0x25:"8*", 0x26:"9(", 0x27:"0)",
   0x28:"\n\n", 0x2B: "\t\t", 0x38: "//",
   0x2C:"  ", 0x2D:"-_", 0x2E:"=+", 0x2F:"[{", 0x30:"]}",  0x32:"#~",
   0x33:";:", 0x34:"'\"",  0x36:",<",  0x37:".>", 0x4f:">", 0x50:"<"
}

with open('keyboard_packets.csv') as csvfile:
    reader = csv.DictReader(csvfile)
    packets = [row['Leftover Capture Data'] for row in reader]

result = ""
caps = False
for packet in packets:
    code = int(packet[4:6],16)
    if code == 0:
       continue
    if code == 0x38:                    # caps toggle
       caps = not caps
       continue
    if code == 0x2a:                    # del key
       result = result[:-1]
       continue
    if (int(packet[0:2],16) == 2 and not caps) or \
       (0x04 <= int(packet[0:2],16) <= 0x1d and caps):  
       # select the character based on the Shift key and Caps Lock
        result += usb_codes[code][1]
    else:
        result += usb_codes[code][0]

print result
```

Запускаем

```no-highligh
$ python2 decode.py  
flag{kaef_1337_1337_kaef_kaef_lol_kek>
```

Флаг: `flag{kaef_1337_1337_kaef_kaef_lol_kek}`

## Misc

Как и в предыдущем разеделе, здесь есть 3 таска на свободные темы

### Что это такое?

>  `--[----->+<]>.++++++.-----------.++++++.[----->+<]>.-[-->+++++<]>-.+[->++<]>.[-->+<]>.+++.---[->++<]>-.+..[-->+<]>+.+.--[->++<]>-.+[-->+<]>.+++.---[->++<]>-.+[-->+<]>++++.+.---[->++<]>-.----.+[-->+<]>++++.--[->++<]>.-.-[-->+<]>.[->++<]>.-.--..+[-->+<]>.+[->++<]>+.-.[-->+<]>-.+++++++.-------[->++<]>.[------>+<]>--.+[--->++<]>+.`

Видим нечто, подозрительно напоминающее Brainfuck. Воспользовавшись любым интерпритатором (например, [этим](https://copy.sh/brainfuck/)) получаем флаг.

Флаг: `flag{0b14abb23a14a56ea5fe2dcaa1ed18b9}`

### Что это такое? 2.0

>  ``` D'`N#9"!<H4{8D05Rd,rO<_-]%ljYE&ffe/b~``u):[qvotsl2pohg-kMiha`ed]#a`_A@VzZY;QuUN6LKoIHGk.JCHAFE>bB;@?>7[54321U/43,+*No-,+$H('&}e#z!~}v<]yxwpunsl2poQg-NMcba'eG]#[ZY}WV[TxXWP8NMLpoONMLEih+*FEDCBA:^>=}|:981U543s+O/.nm%$)"Fg%${z@a}|uzs9wpotsrqj0nPfkjc)g`ed]#a`_^]\[ZYRvVUNMq4PImGFEDCBf@(>=BA@9]=<;{z81UB ```

Тут сложнее. Куча непонятных символов намекает, что это все еще некая программа. Давайте взглянем на [топ-10 эзотерических языков](https://ourcodeworld.com/articles/read/427/top-10-most-complex-and-bizarre-esoteric-programming-languages) и подберем что-то похожее. Больше всех походит на **Malbolge**. Проверив, к примеру, [этим интерпритатором](https://zb3.me/malbolge-tools/#interpreter) получаем флаг.

Флаг: `flag{2f8a49d18bd709cc33d9d926b54d7f20}`

### Что это такое? 3.0

> unai?46e0118.u.086xe.44.3647700801195+

Можно предположить что и это эзотерический код (по инерции с предыдущими тасками). Однако беглый взгляд на популярные эзотеричские языки не находит подходящего. Тогда обратим внимание на структуру строки, предположим это и есть флаг:

```no-highligh
unai?46e0118.u.086xe.44.3647700801195+
flag{????????????????????????????????}
```

Похоже это действительно флаг. Может раскладка неправильная? Давайте попробуем проверить, воспользуемся [этим](https://awsm-tools.com/text/keyboard-layout) сайтом. Перебрав различные варианты раскладок, находим подходящую: Dvorak -> Qwerty.

Флаг: `flag{46d0118efe086bde44e3647700801195}`

## Crypto

На этом CTF нас ждало море ~~говна~~ крипты

### Пришел увидел победил

> Пока писал это послание, написал ещё три <br>
> **uapv{s24qr177t7876p49uqt2635qs9757ts1141p19p9}**

Первый таск скорее всего на шифр Цезаря. Воспользуемся этим [онлайн декодером](https://cryptii.com/pipes/caesar-cipher). Перебрав различные сдвиги, получаем флаг при сдвиге 11.

Флаг: `flag{d24bc177e7876a49fbe2635bd9757ed1141a19a9}`

### Лучше три, чем две

> Расшифруй это <br>
> **SOHTTAKHSFAOWAARCTIALG** <br>
> Ответ переведи в нижний регистр и оберни в flag{}

Попробуем подглядеть в [список популярных шифров](https://www.huntakillerwiththebau.com/cyphers2/). Расшифровывать будем [здесь](https://www.dcode.fr/tools-list#cryptography). В результате выясняем, что это Ceaser Box (есть и такой).

Флаг: `flag{soowhatatrackthisaflag}`

### Woooooow

> Ключик где-то очень рядом. <br>
> **bzou{gkk_hvwg_eo_o_fsoh_bzou_mkqf_bch_xwr}**

Ключик скорее всего Woooooow. Подглядев в [список популярных шифров](https://www.huntakillerwiththebau.com/cyphers2/) с ключами понимаем что это шифр Виженера.

Флаг: `flag{soo_this_is_a_real_flag_your_not_bad}`

### Не Цезарь

> Кажется, это точно не шифр Цезаря. <br>
> Итак, у нас есть шфиротекст **hefi{onixsgkjebujxw}** <br>
> И ключ, но ключ тоже какой-то не такой, единственное что мы имеем 99 116 102.

Можно подумать, что это шифр с ключем, состоящим из 3 чисел. Однако беглый взгляд на [список популярных шифров](https://www.huntakillerwiththebau.com/cyphers2/) не находит подходящего. Что-то тут не так. Слова ***ключ тоже какой-то не такой*** намекают на то, что ключ нужно как-то преобразовать. Попробуем проверить эти числа по таблие ASCII. И действительно, 99 соотвествует `c`, 116 - `t`, 102 - `f`. То есть мы имеем строку `ctf` в качестве ключа. Пробуем расшифровать тем же шифром Виженера, получаем флаг.

Флаг: `flag{vigenerecipher}`

### Do you watch ker?

> А ты?
>  `~ty\x7fchy\x7fGkoy\x7fGzy\x7fe`

Видим строку с escape-последовательностями. Похоже эта строка и есть флаг, просто немного измененная. Откроем интерпритатор python (я воспользуюсь python 2.7) и загрузим туда строку:

```python
>>> s = '~ty\x7fchy\x7fGkoy\x7fGzy\x7fe'
```

Чтобы иметь возможность манипулировать с каждым байтом, преобразем ее в массив байт:

```python
>>> s = bytearray(s)
```

Предположим, что это флаг. Тогда строка должна начинаться на `flag`

```python
>>> s2 = 'flag'
>>> s2 = bytearray(s2)
```

Попробуем сравнить байты используя операции вычитания и XOR.

```python
>>> [s[i] - s2[i] for i in range(4)]
[24, 8, 24, 24]
>>> [s[i] ^ s2[i] for i in range(4)]
[24, 24, 24, 24]
```

Похоже это все таки флаг, и чтобы его получить, нужно произвести XOR над всеми байтами строки с числом 24:

```python
>>> res = [c ^ 24  for c in s]
>>> bytearray(res)
bytearray(b'flag{pag_swag_bag}')
```

Флаг: `flag{pag_swag_bag}`

### Ну это просто "гг изи, го некст"

> Ну это просто "гг изи, го некст" <br>
> key: 0123456789abcdef iv: 0123456789abcdef <br>
> enc: 9c268e2ca4480c908bb3ffee7fe72ed2289e2e2473bfaccf2a3d33d632385ece

Ну это просто гг изи AES-CBC. Вставляем [сюда](https://www.devglan.com/online-tools/aes-encryption-decryption), получаем флаг.

Флаг: `flag{this_is_real_AES?}`

### Изи изи

> MDExMDAxMTAgMDExMDExMDAgMDExMDAwMDEgMDExMDAxMTEgMDExMTEwMTEgMDExMDAxMDEgMDEx MDAwMDEgMDExMTAwMTEgMDExMTEwMDEgMDEwMDAwMTAgMDExMDEwMDEgMDExMDExMTAgMDExMDAw MDEgMDExMTAwMTAgMDExMTEwMDEgMDEwMDEwMDAgMDExMDAwMDEgMDExMDEwMDAgMDExMDAwMDEg MDExMTExMDE=

Знак равенства в конце жирно намекает на то что это base32 либо base64. Воспользовавшись любым декодером base32 (например, [этим](https://emn178.github.io/online-tools/base32_decode.html)), понимаем, что это все таки base64, декодировав который (например, [этим](https://emn178.github.io/online-tools/base64_decode.html)), получаем следующий текст:

```no-highligh
01100110 01101100 01100001 01100111 01111011 01100101 01100001 01110011 01111001 01000010 01101001 01101110 01100001 01110010 01111001 01001000 01100001 01101000 01100001 01111101
```

Это текст закодированный бинарно. Декодируем текст (например, [этим](https://www.rapidtables.com/convert/number/binary-to-ascii.html)), получаем флаг.

Флаг: `flag{easyBinaryHaha}`

### Кот криптограф

> Мой кот прошелся по клавиатуре. Хотя нет, это точно какой-то шифр <br>
> **ABABBBAAAAAAAABAAAAAAAABAABBABABBAAABBAAABBABBAABAAAAAAAAAABAAAAAAAABAABBABABBAA**

Вновь некий шифр. Подглядев в [список популярных шифров](https://www.huntakillerwiththebau.com/cyphers2/) с ключами понимаем что это шифр Бэйкона (или бекона, мне пофиг). Рашифровываем [тут](https://www.dcode.fr/bacon-cipher), получаем **MRBACONNOTABACON**.

Флаг: `flag{mrbaconnotabacon}`

### Подсчитаем буквы

> Подсчитаем буквы! <br>
> Формат флага: обернуть найденный текст в flag{} <br>
> [[crypto_st.txt](/files/crypto_st.txt?raw=true)]

Намек понят, текст получен из исходного подменой каждой буквы на некоторую другую (простейший шифр подстановки). Текста достаточно, чтобы разглядеть закономерности, провести статистический анализ и постепенно декодировать текст. Многое об этом есть в [этой статье](http://practicalcryptography.com/ciphers/simple-substitution-cipher/). Руками слишком долго и не интересно. В той статье есть [ссылка на статью](http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-simple-substitution-cipher/) о том, как автоматически взломать такой шифр. Там присутсвуют ссылки непосредственно на скрипты. Я прилагаю их слегка измененными в данном репозитории в директории substitute. Скрипт рандомно генерирует ключи, так что иногда он может выдавать неверный результат (его стоит перезапустить).

```no-highligh
$ python2 decrypt.py ../files/crypto_st.txt  
Substitution Cipher solver, you may have to wait several iterations

best score so far: -6930.49408729 on iteration 1  
best key: QWERTYUIOPASDFGHJKLMNBVCXZ
Kutuzov, like all old people, slept...
...
... Flag is ooooh_you_are_from_Anglia?
...
```

Флаг: `flag{ooooh_you_are_from_Anglia?}`

### The Watch Us

> Эти странные символы похоже из какой-то древней эпохи, возможно 11 - 13 век. <br>
> [[cipher.PNG](/files/cipher.PNG?raw=true)]

![cipher](/files/cipher.PNG?raw=true)

В этот придется гуглить. Мне помог запрос в гугл-картинки: trinagles crosses cipher. Им оказывается The Knights Templar's Cipher. Воспользовавшись, например, [этим декодером](https://www.dcode.fr/templars-cipher) получаем флаг.

Флаг: `flag{knightsofctf}`

### Super Hash

> `37 64 37 39 33 30 33 37 61 30 37 36 30 31 38 36` <br>
> `35 37 34 62 30 32 38 32 66 32 66 34 33 35 65 37` <br>
> Не забудь обернуть результат в flag{xxx}, где xxx результат

Можно долго думать, что тут дано. Первое, что приходит в голову - нам даны 32 байта записанных в десятиричном формате. При соотвествующем преобразовании, получаем нечитаемый текст:

```python
>>> a = [37, 64, 37, 39, 33, 30, 33, 37, 61, 30, 37, 36, 30, 31, 38, 36, 35, 37, 34, 62, 30, 32, 38, 32, 66, 32, 66, 34, 33, 35, 65, 37]  
>>> bytearray(a)  
bytearray(b'%@%\'!\x1e!%=\x1e%$\x1e\x1f&$#%">\x1e & B B"!#A%')
```

А если это 32 байта, представленных все же в 16-ричном формате?

```python
>>> a2 = [0x37, 0x64, 0x37, 0x39, 0x33, 0x30, 0x33, 0x37, 0x61, 0x30, 0x37, 0x36, 0x30, 0x31, 0x38, 0x36, 0x35, 0x37, 0x34, 0x62, 0x30, 0x32, 0x38, 0x32, 0x66, 0x32, 0x66, 0x34, 0x33, 0x35, 0x65, 0x37]  
>>> bytearray(a2)  
bytearray(b'7d793037a0760186574b0282f2f435e7')
```

А вот это уже похоже на хэш. Гуглим, находим по первой же ссылке, что это хэш MD5 от `world`

Флаг: `flag{world}`

### Samuel Mo.-

> Послушай эту запись. <br>
> **Формат флага: flag{sha1} , всё в lowercase** <br>
> [[task.wav](/files/task.wav?raw=true)]

Скачиваем запись, прослушиваем, слышим морзянку. Грузим морзянку в декодер (например, [этот](https://morsecode.scphillips.com/labs/audio-decoder-adaptive/)), получаем строку **FLAGISC601F933976F27B6C33640C3CA7E808E6BCA5FCF**

Флаг: `flag{c601f933976f27b6c33640c3ca7e808e6bca5fcf}`

## Reverse

В разделе реверса к моему великому сожалению был всего один таск

### Бинарка для детей

> Разомнись на этом бинарнике <br>
> [[rev1](/files/rev1?raw=true)]

Воспользуемся прекрасным декомпилятором Ghidra от NSA. Вгружаем файл, анализируем всё, смотрим результат декомпиляции функции main

![decompile result](/files/ghidra.png?raw=true)

Явно видим строку `kaljv4;k=k=5n=<55ol=9545nh5nn9;8n<4n9p`, которая XOR-ится с 0xD. Сделаем тоже самое:

```python
>>> s = 'kaljv4;k=k=5n=<55ol=9545nh5nn9;8n<4n9p'
>>> s = bytearray(s)
>>> m = [c ^ 0xD for c in s]
>>> bytearray(m)
bytearray(b'flag{96f0f08c0188ba04898ce8cc465c19c4}')
```

Флаг: `flag{96f0f08c0188ba04898ce8cc465c19c4}`

## Ссылки

Binwalk by ReFirmLabs: [https://github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) <br>
JohnTheRipper by magnumripper: [https://github.com/magnumripper/JohnTheRipper](https://github.com/magnumripper/JohnTheRipper) <br>
Rockyou wordlist: [https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt) <br>
Wireshark by Wireshark Foundation: [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html) <br>
Reverse Engineer USB keystroke by AliBawazeEer: [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-...](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4) <br>
Brainfuck interpreter: [https://copy.sh/brainfuck/](https://copy.sh/brainfuck/) <br>
Top 10 Most Complex and Bizarre esoteric programming languages: [https://ourcodeworld.com/articles/read/427/top-10...](https://ourcodeworld.com/articles/read/427/top-10-most-complex-and-bizarre-esoteric-programming-languages) <br>
Malbolge interpreter: [https://zb3.me/malbolge-tools/#interpreter](https://zb3.me/malbolge-tools/#interpreter) <br>
Keyboar layout converter: [https://awsm-tools.com/text/keyboard-layout](https://awsm-tools.com/text/keyboard-layout) <br>
Caesar Cipher Encoder/Decoder: [https://cryptii.com/pipes/caesar-cipher](https://cryptii.com/pipes/caesar-cipher) <br>
Online crypto tools: [https://www.dcode.fr/tools-list#cryptography](https://www.dcode.fr/tools-list#cryptography) <br>
Online AES Encryption and Decryption: [https://www.devglan.com/online-tools/aes-encryption-decryption](https://www.devglan.com/online-tools/aes-encryption-decryption) <br>
Base64 online decoder: [https://emn178.github.io/online-tools/base64_decode.html](https://emn178.github.io/online-tools/base64_decode.html) <br>
Binary to Text translator: [https://www.rapidtables.com/convert/number/binary-to-ascii.html](https://www.rapidtables.com/convert/number/binary-to-ascii.html) <br>
About substitution cipher: [http://practicalcryptography.com/ciphers/simple-substitution-cipher/](http://practicalcryptography.com/ciphers/simple-substitution-cipher/) <br>
Cryptoanalysis of substitution cipher: [http://practicalcryptography.com/cryptanalysis/stochastic-searching/crypt...](http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-simple-substitution-cipher/) <br>
Morse Code Adaptive Audio Decoder: [https://morsecode.scphillips.com/labs/audio-decoder-adaptive/](https://morsecode.scphillips.com/labs/audio-decoder-adaptive/) <br>
Ghidra Software Reverse Engineering Framework: [https://github.com/NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)
