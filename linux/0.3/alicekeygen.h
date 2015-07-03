#ifndef _ALICEKEYGEN_H
#define _ALICEKEYGEN_H

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include "sha256.h"

#define MJR_VER 0
#define MIN_VER 3

#define SERIESXSERIAL_SIZE 13
#define MAX_NUM_MAC 16
#define MAC_SIZE 6
#define WPA_SIZE 24
#define CRLF_SIZE 2
#define LF 0x0A
#define CR 0x0D
#define SHA256_SIZE 32

#define TRUE 1
#define FALSE 0

#define SUCCESS 0
#define FAILURE 1
#define KEYFOUND 2

#define NO_ERROR 0
#define FILE_ERR 1
#define FILE_EXS 2
#define MEM_ERR  3
#define QK_ERROR 4
#define QK_UNABL 5
#define QK_INCON 6

#define NONE    0
#define GENFILE 1
#define FINDKEY 2
#define QK_MODE 3

#define DEFAULT_BUFFER_SIZE_MB 50
#define PRINT_RATE 20000
#define MAX_SERIAL 1000000

struct option
{
    unsigned long int ssid;
    char* macAddrWifi; 
    char* file;
    char* fileMN; 
    unsigned long int bufferSize;
    unsigned long int series;
    unsigned long int startSerial;
    unsigned long int endSerial;
    int opMode;
    int splitDict;
    int oneMac;
    int wpaChars;
};

#endif /* _ALICEKEYGEN_H */
