*Alicekeygen* è un software per il recupero delle chiavi WPA dei router Alice Telecom AGPF.

Il tool prevede tre modalità di funzionamento:

  * modo istantaneo
  * modo dizionario
  * modo ricerca

===Modo istantaneo===

Il tool genera immediatamente una lista di wpa candidate da provare. Occorre specificare l'SSID di rete, il mac address wifi della stessa rete e il file config aggiornato (incluso nel pacchetto).

{{{
$ ./alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -q agpf_config.txt
}}}

===Modo dizionario===

Il tool genera un file dizionario da passare a programmi esterni di bruteforcing quali [http://aircrack-ng.org/ aircrack-ng] o [http://code.google.com/p/pyrit/ pyrit] per recuperare la chiave WPA corretta. Una vasta gamma di opzioni permettono di raffinare il dizionario e ridurne le dimensioni.
Il tempo necessario al recupero della chiave dipende ovviamente dalla velocità della macchina (CPU, estensioni CUDA, etc..) e dalla dimensione del dizionario. Per alcune stime sui tempi massimi di recupero della chiave si veda la sezione "casi d'uso modalità dizionario". I programmi esterni di bruteforcing, per poter funzionare correttamente, necessitano del file 4-way-handshake.

In questa modalità il recupero della chiave è pressochè *garantito*.

Come si recupera il 4-way-handshake nei pacchetti EAPOL? Ecco un'ottima [http://aircrack-ng.org/doku.php?id=cracking_wpa guida].

Alcuni esempi:

{{{
$ ./alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -o dict.txt
}}}

Genera il dizionario dict.txt per la rete SSID Alice-12345678 e MAC wifi 00:23:8E:01:02:03

{{{
$ ./alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -e 69102 -o dict.txt
}}}

Genera il dizionario dict.txt per la rete SSID Alice-12345678, MAC wifi 00:23:8E:01:02:03 e serie 69102

{{{
$ ./alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -sl 16384 -e 67903 -o dict.txt
}}}

Genera il dizionario dict.txt per la rete SSID Alice-12345678, MAC wifi 00:23:8E:01:02:03, serie 67903 e serial number maggiore o uguale a 16384.

{{{
$ ./alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -sh 30000 -e 67903 -o dict.txt
}}}

Genera il dizionario dict.txt per la rete SSID Alice-12345678, MAC wifi 00:23:8E:01:02:03, serie 67903 e serial number minore o uguale a 30000.

===Modo ricerca===

Permette 1) di verificare che una data chiave wpa venga effettivamente generata da alicekeygen e 2) recuperare i dati associati a quella chiave (serie e seriale del router alice)

{{{
$ ./alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -w 1234abcd1234abcd1234abcd
}}}

Nell'esempio si verfica che la chiave wpa 1234abcd1234abcd1234abcd sia presente nel dizionario generato da rete SSID Alice-12345678, MAC wifi 00:23:8E:01:02:03.

= News =

Aggiunta versione 0.3 per WindowsXP, Vista, Windows7, Linux allversion, MacOSX [http://code.google.com/p/alicekeygen/downloads download]

=Download=

Le release vengono pubblicate nella [http://code.google.com/p/alicekeygen/downloads sezione download]

=Compilazione=

Il tool è scritto interamente in C e compila sotto Linux (qualsiasi versione), Windows XP/Vista/Win7 e MacOSX.

===Linux==

Per compilare sotto Linux occorre dare i seguenti comandi da console:

{{{
$ gcc alicekeygen.c sha256.c -w -o alicekeygen
$ chmod +x alicekeygen
}}}

ed eseguire con:

{{{
$ ./alicekeygen
}}}

===Windows===

Nessuna compilazione richiesta. Nella sezione download è presente l'applicazione già compilata e funzionante.

===MacOSX===

Occorre scaricare ed installare il pacchetto [http://developer.apple.com/xcode/ XCode]. La procedura è identica a quella per Linux.

=Casi d'uso in modo dizionario=

Riporto alcuni casi d'uso con tempi di recupero della password wpa nella modalità dizionario. E' ovvio che queste stime dipendono praticamente dai soli tool di bruteforce e dalla potenza della macchina host.

Ambiente di test:

  * Modello: Apple MacBook
  * CPU: 2.4 GHz Core 2 Duo
  * GPU: GeForce 9400 GM
  * Cracking tool: Pyrit + CUDA

La macchina testa all'incirca 1500 PMK/sec.

==Scenario 1==

Parametri noti:

  * SSID della rete Alice
  * MAC address wifi

Alicekyegen genera mediamente 32x10^6^ chiavi WPA. Tempo massimo di recupero della chiave: 32x10^6^ / 1500 = 21332 sec. => 6 ore circa. 

==Scenario 2==

Parametri noti:

  * SSID della rete Alice
  * MAC address wifi
  * Serie del router

In questo caso i numero delle chiavi scende quasi di un ordine di grandezza, mediamente 4x10^6^. Tempo massimo di recupero della chiave: 4x10^6^ / 1500  = 2666 sec. => 40 minuti circa. 

=Links=

[http://www.gianlucaghettini.net Pagina blog del progetto]

[http://wifiresearchers.wordpress.com/2010/06/02/alice-agpf-lalgoritmo/ White Hats Crew: Algoritmo per router Alice AGPF]

[http://aircrack-ng.org/doku.php?id=cracking_wpa Aircrack-ng: tutorial WPA cracking]

[http://aircrack-ng.org/ Aircrack homepage]

[http://code.google.com/p/pyrit/ Pyrit homepage]

=Come contribuire=

Per idee, suggerimenti, nuove opzioni o per collaborare al miglioramento del tool ecco la [http://www.gianlucaghettini.net/alicekeygen-generatore-wordlist-wpawpa2-psk-alice-telecom pagina] del blog:


=Note=

Per maggiori informazioni sul funzionamento del sistema di sicurezza WPA dei router wifi Alice Telecom AGPF si veda [http://wifiresearchers.wordpress.com/2010/06/02/alice-agpf-lalgoritmo questo link].


=Crediti=

Il tool si basa sul risultati ottenuti dalla White Hat Crew alla quale vanno i ringraziamenti per l'ottimo [http://wifiresearchers.wordpress.com/2010/06/02/alice-agpf-lalgoritmo lavoro].


