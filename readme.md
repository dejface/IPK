#Cieľ projektu
Cieľom projektu je implementácia serveru, ktorý bude komunikovať protokolom HTTP a bude zaistovať preklad doménových mien.

#Riešenie projektu
Pre implementáciu projektu som zvolil jazyk Python, pretože je to jeden z mojich obľúbených jazykov.
Pri riešení som využíval knižnice Pythonu, konkrétne ***sys*** (spracovanie argumentov, exit kódy programu), ***socket*** (implementácia servera pomocou socketu) a ***re*** (podpora regulárnych výrazov).

#Funkcionalita projektu
Pomocou knižnice ***socket*** som vytvoril najprv server, potom som nastavil komunikáciu medzi klientom a servervom pomocou funkcie *socket.accept()*, pomocou funkcie *socket.decode()* sa dekóduju dáta od klienta s ktorými následne pracujem v nekonečnom cykle. Po spracovaní požiadavku od kienta sa dáta opäť zakódujú a posiela sa odpoveď pomocou *socket.sendall()* späť klientovi a ukončí sa s ním spojenie pomocou *socket.close()*.
Úspešne spracované požiadavky vracajú kód 200, neúspešné 4xx alebo 500. Server je ukončený po stlačení klávesovej kombinácie **CTRL + C**.
Program podporuje metódy POST a GET.

#Výstup projektu
Výstupom projektu je spracovaný požiadavok v tvare:
**GET** - *DOTAZ:TYP=ODPOVED*
**POST** - *DOTAZ:TYP*

#Spustenie prjektu
make run PORT=*cislo*
*cislo* je číslo PORTU na ktorom bude bežať server v rozmedzí 1023 < cilso < 65535