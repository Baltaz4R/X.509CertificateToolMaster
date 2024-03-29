# Пројектни задатак 2018/2019.

Циљ пројектног задатка је боље разумевање структуре X.509 сертификата, као и начина
њиховог генерисања и употребе. У ту сврху задатак подразумева пројектовање и
имплементацију апликације са графичким корисничким интерфејсом у програмском
језику _Java_ која треба да омогући следеће функционалности:

- генерисање новог пара кључева за X.509 сертификат,
- извоз/увоз постојећег пара кључева за X.509 сертификат,
- преглед детаља постојећих парова кључева за X.509 сертификат,
- потписивање X.509 сертификата,
- извоз креираног X.509 сертификата.

Детаљи сваке од функционалности дефинисане су на различит начин за различите групе
за израду пројекта, које су дате у наставку документа (Прилог 1). Сваки студент
имплементираће пројекат у складу са поставком групе која му буде додељена. Како би
студенти били фокусирани на сигурносни аспект, неће морати самостално да
имплементирају графички кориснички интерфејс, већ ће им исти бити обезбеђен у облику
.jar библиотеке. Упутство за коришћење .jar библиотеке дато је у наставку документа
(Прилог 2).

Напомене:

1. Пројекат се ради самостално. Сви студенти који прате предмет су аутоматски
    пријављени за израду пројекта. Студент треба да изради пројекат из групе која се
    добија на следећи начин: _gr =_ ( _brind mod 30 ) + 1_ , где је _gr_ број групе коју студент
    треба да ради, а _brind_ број индекса студента (нпр. студент са индексом 2017/0897
    треба да ради групу 28 _= ( 897 mod 30 ) + 1_ ).
2. Сви предати пројекти ће бити пропуштени кроз апликацију за проверу сличности
    програмског кода. Уколико се провером установи да су два или више предатих
    пројеката са већим степеном сличности од дозвољеног, сви аутори ће бити
    пријављени дисциплинској комисији Факултета.


3. Није дозвољено коришћење готових алата за рад са сертификатима (нпр. _keytool_) у
    реализацији пројекта.
4. Одбрана пројектног задатка ће бити организована у јунском и септембарском року
    неколико дана пре одржавања испита у складу са расположивошћу сала. Могућа је
    и одбрана у предроку крајем маја уколико за то буде услова.
5. Пројекат се предаје најкасније 48 сати пре одбране као ZIP архива на начин који ће
    студентима благовремено бити саопштен.
6. Пројекат носи 20 поена. Од тога 15 поена је могуће освојити за исправно
    реализован пројекат одбрањен на усменој одбрани, док се преосталих 5 поена
    може освојити успешном реализацијом модификације на самој одбрани пројекта.
7. Корисни ресурси за пројекат:

    a. https://www.ietf.org/rfc/rfc5280.txt

    b. https://docs.oracle.com/javase/7/docs/api/java/security/package-summary.html

    c. https://docs.oracle.com/javase/7/docs/api/javax/crypto/package-summary.html

    d. https://www.bouncycastle.org/

8. За сва питања и нејасноће у вези пројекта писати на aki@etf.rs, majav@etf.rs,
    zarko@etf.rs или pavle.vuletic@etf.rs.


**Прилог 1. Детаљи неопходних функционалности распоређени по групама**

**Група 10.**

Приликом генерисања новог пара кључева за X.509 сертификат треба подржати само DSA
алгоритам (са свим дужинама кључа подржаним у графичком корисничком интерфејсу) у
комбинацији са свим варијантама хеш алгоритама подржаним у графичком корисничком
интерфејсу. Кориснику треба понудити да унесе следеће информације: величину кључа,
верзију сертификата, период важења, серијски број и информације о кориснику (CN, OU,
O, L, ST, C). Треба подржати само верзију 3 сертификата. Кориснику треба понудити да
опционо може да унесе и следеће екстензије: идентификатор кључа власника
сертификата (subject key identifier), алтернативна имена корисника (subject alternative
name) и проширено коришћење кључа (extended key usage). Омогућити за екстензије да се
означи да ли су критичне или не. Корисник треба да има могућност да у апликацији сачува
генерисани пар кључева под жељеним именом.

Приликом извоза пара кључева за X.509 сертификат кориснику треба омогућити да
одабере путању до фајла за извоз (креира фајл, ако не постоји) и унесе лозинку којом ће
заштити фајл. Приликом увоза пара кључева за X.509 сертификат кориснику треба
омогућити да одабере фајл за увоз и унесе лозинку којом је фајл заштићен, а затим сачува
увезени пар кључева под жељеним именом. Треба подржати само PKCS #12 формат фајла
(екстензија .p12).

За све постојеће парове кључева омогућити структурирани приказ свих поља дефинисаних
у опису функционалности генерисања новог пара кључева за X.509 сертификат уз додатак
информација о потпису за оне парове који су потписани.

Приликом потписивања X.509 сертификата потребно је омогућити да се за одабрани пар
кључева генерише захтев за потписивање сертификата (CSR) у PKCS #10 формату
(екстензија .csr). За све парове кључева који имају право да потписују друге сертификате
(CA услов) омогућити да могу да потпишу претходно генерисане захтеве за потписивање
сертификата. Процедура је да се у овом случају најпре учитају све информације из захтева
за потписивање сертификата, осим екстензија, затим се омогући измена оних параметара
за које је задужен сертификациони ауторитет и након тога потврди потписивање захтева.
Резултат ове радње је креирање CA reply фајла у PKCS #7 формату (екстензија .p7b), који је
након тога могуће увести за одговарајући пар кључева, чиме он добија потпис.

За креиране X.509 сертификате потребно је омогућити извоз сертификата или читавог
ланца (уколико је могуће) у base-64 енкодираном X.509 формату (PEM) и бинарном
формату (DER) (у оба случаја екстензија фајла је .cer). Кориснику омогућити да одабере
путању до фајла за извоз (креира фајл, ако не постоји).

**Прилог 2. Упутство за коришћење .jar библиотеке за креирање пројекта**

Студентима су на располагању две библиотеке _jdatepicker-1.3.4.jar_ и _Х509_2019.јаr_ помоћу
којих треба реализовати апликацију за генерисање и потписивање _Х509_ сертификата.
Библиотеке треба учитати у оквиру новокреираног _јаvа_ пројекта подешавањем _java build
path_-a у конфигурацији пројекта.

Осим библиотека потребно је направити и _config.txt_ фајл у оквиру кога се налази
конфигурација за групу коју студент треба да имплементира. У овом фајлу треба набројати
који алгоритам и које екстензије треба да буду подржани у графичком корисничком
интерфејсу (раздвајати их новим редом). Вредности параметара су: _DSA, RSA_ и _EC_ за
алгоритме; _authority key identifier, subject key identifier, key usage, certificate policies, subject
alternative name, issuer alternative name, subject directory attributes, basic constraints, name
constraints, extended key usage_ и _inhibit any policy_ за екстензије; треба навести и _extensions
rules_ параметар који омогућава да се у графичком корисничком интерфејсу аутоматски
успоставе сва додатна правила која важе приликом постављања екстензија. Приликом
учитавања фајла, апликација не прави разлику између малих и великих слова, а није
битан ни редослед навођења. При покретању апликације у оквиру командне линије треба
задати путању до овог фајла.

Након тога треба креирати пакет _implementation_ и у оквиру њега класу _MyCode_ која треба
да буде изведена из класе _x509.v3.CodeV3_. Ова класа је дата у оквиру пакета _x509.v3_ у
библиотеци _Х509_2019.јаr_. У склопу решавања пројектног задатка потребно је
имплементирати наслеђене методе. Дозвољено је уводити нове класе, по потреби.
Улазна тачка програма налази се у класи _Х509_ у библиотеци _Х509_2019.јаr_.

На располагању је и _ETFrootCA.p12_ који треба учитати у апликацију по завршетку пројекта
и који се може користити као ауторитет за потписивање сертификата (шифра је _root_).
