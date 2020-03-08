# Cieľ projektu
Cieľom projektu je implementácia serveru, ktorý bude komunikovať protokolom HTTP a bude zaistovať preklad doménových mien.

# Riešenie projektu
Pre implementáciu projektu som zvolil jazyk Python, pretože je to jeden z mojich obľúbených jazykov.

Pri riešení som využíval knižnice Pythonu, konkrétne ***sys*** (spracovanie argumentov, exit kódy programu), ***socket*** (implementácia servera pomocou socketu) a ***re*** (podpora regulárnych výrazov).

# Funkcionalita projektu
Pomocou knižnice ***socket*** som vytvoril najprv server, potom som nastavil komunikáciu medzi klientom a servervom pomocou funkcie *socket.accept()*, pomocou funkcie *socket.decode()* sa dekóduju dáta od klienta s ktorými následne pracujem v nekonečnom cykle. Po spracovaní požiadavku od kienta sa dáta opäť zakódujú a posiela sa odpoveď pomocou *socket.sendall()* späť klientovi a ukončí sa s ním spojenie pomocou *socket.close()*.

Program podporuje metódy POST a GET.

Pri metóde GET úspešné spracovaná požiadavka vracia HTTP respone 200 OK, neúspešná 400 bad request.
Pri metóde POST pokiaľ je aspoň jeden požiadavok platný a nájde odpoveď, HTTP response je 200 OK. Pokiaľ nie je nájdená odpoveď a niektorí z požiadavkov nie je validný, HTTP response je 400 Bad Request. Pokiaľ sa nenájde žiadna odpoveď na požiadavky, HTTP response je 404 Not Found.

Server je ukončený po stlačení klávesovej kombinácie **CTRL + C**.

# Výstup projektu
Výstupom projektu je spracovaný požiadavok v tvare:

**GET** - *DOTAZ:TYP=ODPOVED*

**POST** - *DOTAZ:TYP*

# Spustenie prjektu
Po rozbalení .zip archívu:

make run PORT=*cislo*

*cislo* je číslo PORTU na ktorom bude bežať server v rozmedzí 1023 < *cislo* < 65535
