# IPK Projekt 2 - Varianta ZETA: Sniffer paketů

## Príklad spustenia
1. Po rozbalení archívu je potrebné preložiť projekt pomocou `make`
2. Spustenie 
    * `./ipk-sniffer -i *interface* [-p *port*] [-t] [-u] [-n *num*] `
        * *interface* - názov rozhrania na ktorom budú pakety zachytávané
        * *port* - číslo portu v rozmedzí od 0 do 65535 na ktorom budú pakety filtrované
        * -t - zachytáva iba TCP pakety
        * -u - zachytáva iba UDP pakety
        * *num* - musí byť väčšie ako 0, zobrazuje počet zachytených paketov
    * spustenie si vyžaduje administrátorské práva, aby sniffovanie mohlo byť uskutočnené. V tom prípade treba spúšťať s príkazom `sudo`
        * `sudo ./ipk-sniffer -i *interface* [-p *port*] [-t] [-u] [-n *num*] `

## Zoznam odovzdaných súborov
* xorave05.tar
    - ipk-sniffer.c
    - ipk-sniffer.h
    - manual.pdf
    - README.md
