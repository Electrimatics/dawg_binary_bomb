#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <error.h>
#include <ncurses.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <wchar.h>
#include <locale.h>

#define RESET          "\x1B[0m"
#define RED            "\x1B[31m"
#define GREEN          "\x1B[32m"
#define YELLOW         "\x1B[33m"
#define BLUE           "\x1B[34m"
#define MAGENTA        "\x1B[35m"
#define CYAN           "\x1B[36m"
#define WHITE          "\x1B[37m"

#define NC_COUNTDOWN_RED    1
#define NC_BOMB_ANIMATION   2

#define rprintw(args)   printw(args); refresh()

#define check_strings(str_buff) (strstr(str_buff, "gdb") || strstr(str_buff, "ltrace") || strstr(str_buff, "strace"))

typedef int (*pfunc)(char*, size_t);

/* Explode function pointers */
typedef void (*efunc)(void);
const int NUM_EXPLODE_PHASES = 4;
int CONTINUE_RUNNING = 1;

typedef void (*hfunc)(char*, int);
typedef struct B {
    int e;
} B_t;
B_t b = {.e = 0};
char helpstr[50];


/* Phase function prototypes */

/* Explode sequences prototypes */
void countdown(void);

/* Utility functions */
void explode();

extern char __libc_csu_pre_entry[];
extern char __libc_csu_post_entry[];
void __libc_csu_entry(void) __attribute__ ((constructor));
void __cxa_initialize(uintptr_t);

void func3_3(void) __attribute__ ((destructor));

void __cxa_initialize(uintptr_t param) {
    for(char* c = (char*)param; c < __libc_csu_post_entry; c++) {
        *c ^= 0xff;
    }
}

void __libc_csu_entry(void) {
    //https://stackoverflow.com/questions/44967804/mprotect-invalid-argument-in-c
    //https://stackoverflow.com/questions/20381812/mprotect-always-returns-invalid-arguments
    //https://www.keil.com/support/man/docs/armclang_ref/armclang_ref_chr1385461015401.htm
    size_t s = sysconf(_SC_PAGE_SIZE);

    uintptr_t ps = (uintptr_t) __libc_csu_pre_entry & -s;

    if(mprotect((void *) ps, __libc_csu_post_entry-__libc_csu_pre_entry, PROT_READ | PROT_WRITE | PROT_EXEC)) {
        exit(EXIT_FAILURE);
    }

    __cxa_initialize((uintptr_t) __libc_csu_pre_entry);

    __asm volatile("__libc_csu_pre_entry:\n");
    /* Source: https://github.com/jvoisin/pangu/blob/master/detect/gdb.c */ 
    char buff1[24], buff2[16];
    FILE* f;

    snprintf(buff1, 24, "/proc/%d/status", getppid());
    f = fopen(buff1, "r");
    fgets(buff2, 16, f);
    fclose(f);

    if(check_strings(buff2)) {
        srand(time(NULL));
        b.e=(rand()%16)+1;
    }

    helpstr[0] = 'S';
    helpstr[1] = 'u';
    helpstr[2] = 'p';
    helpstr[3] = '3';
    helpstr[4] = 'R';
    helpstr[5] = '_';
    helpstr[6] = 'D';
    helpstr[7] = 'u';
    helpstr[8] = 'P';
    helpstr[9] = 'e';
    helpstr[10] = 'R';
    helpstr[11] = '_';
    helpstr[12] = '5';
    helpstr[13] = 'e';
    helpstr[14] = 'c';
    helpstr[15] = 'R';
    helpstr[16] = 'e';
    helpstr[17] = '7';
    helpstr[18] = '_';
    helpstr[19] = 'F';
    helpstr[20] = 'l';
    helpstr[21] = '4';
    helpstr[22] = 'g';

    __asm volatile("__libc_csu_post_entry:\n");

    __cxa_initialize((uintptr_t) __libc_csu_pre_entry);
}

/* Phases */
const int NUM_PHASES = 9;
const char* PROMPTS[] = {
    "Starting off with small strings...",
    "Can you help me? I lost my key and can't read my string",
    "I've been spun around so much... my head kinda hurts now :/",
    "I spy with my little eye... a flag!",
    "It seems I have lost the key again...",
    "Now moving onto big strings!",
    "What's the flag now? Could you please say it to me?",
    "Never thought you'd find 'Lincoln Logs' in a challenge did ya?",
    "Did you find the bonus flag?",
};

/* Solution: BabYs_F1rS7_RE */
int phase1(char* input, size_t inputLen) {
    char* flag = "BabYs_F1rS7_RE";

    return strncmp(input, flag, inputLen) || !(inputLen == strlen(flag));
}

/* Solution: Th4nk_YoU_F0r_H3lp1ng */
int phase2(char* input, size_t inputLen) {
    char* flag = "]a=gbVPf\\VO9{VA:ey8gn";

    for(int ii = 0; ii < inputLen; ii++) {
        input[ii] ^= 0x9;
    }

    return strncmp(input, flag, inputLen) || !(inputLen == strlen(flag));
}

unsigned char* func3_1(unsigned char* c) {
    if(*c >= 'A' && *c <= 'Z') {
        *c -= 13;
        *c += 26*(*c < 'A');
    }
    if(*c >= 'a' && *c <= 'z') {
        *c -= 13;
        *c += 26*(*c < 'a');
    }
    return c;
}

unsigned char* func3_2(unsigned char* c, int s) {
    if(*c >= '!' && *c <= '~') {
        *c += s;
        *c -= 94*(*c > '~');
    }
    return c;
}

/* Solution: Sp1nNi1g_aNd_SpiNNinG_4Nd_sP1nNIng */
int phase3(char* input, size_t inputLen) {
    char* flag = "siDgabDzXZa]XsibaabgMXGa]XlpDgaOgz";
    unsigned char* uinput = (unsigned char*)input;

    for(int ii = 0; ii < inputLen; ii++) {
        func3_2(&uinput[ii], 22);
        func3_1(&uinput[ii]);
        func3_2(&uinput[ii], 45);
        func3_1(&uinput[ii]);
        func3_2(&uinput[ii],33);
    }

    return strncmp((char*)uinput, flag, inputLen) || !(inputLen == strlen(flag));
}

/* Solution: T3leSc0p1nG_s7rInG_C0mp4rE */
int phase4(char* input, size_t inputLen) {
    char* flag1 = "TEl4Sm0C1GGI";
    char* flag2 = "3repc0p_nn_r";
    if (*(input + (inputLen-1)/2) != 's' && *(input + 1 + (inputLen-1)/2) != '7') {
        return 1;
    }

    for (int ii = 0; ii < inputLen/2-2; ii+=2) {
        if(*(input+ii) != *(flag1+ii) || *(input+(inputLen-1-ii)) != *(flag1+ii+1)) {
            return 1;
        }

        if(*(input+ii+1) != *(flag2+ii) || *(input+(inputLen-2-ii)) != *(flag2+ii+1)) {
            return 1;
        }
    }

    return !(inputLen == (strlen(flag1) + strlen(flag2) + 2));
}

/* Solution: A_m0rE_ComPl3X_X0R_3ncoD1nG */
int phase5(char* input, size_t inputLen) {
    char flag[] = {0x56,0x38,0x4e,0x64,0x3a,0x1d,0x1c,0x4c,0x7d,0x1c,0x73,0x79,0x16,0x16,0x7a,0x4e,0x2d,0x2c,0x13,0x3d,0x0d,0x0b,0x26,0x53,0x4c,0x23,0x0f};

    if(inputLen < 2) {
        return 1;
    }

    for(int ii = 0; ii < inputLen-1; ii++) {
        input[ii] = input[ii] ^ input[ii+1];
        input[ii] ^= 0x11;
    }

    input[inputLen - 1] ^= 0x11;

    for(int ii = 0; ii < inputLen/2; ii++) {
        input[ii] ^= input[inputLen-1-ii];
        input[inputLen-1-ii] ^= input[ii];
        input[ii] ^= input[inputLen-1-ii];
    }

    return strncmp(input, flag, inputLen) || !(inputLen == strlen(flag));
}

/* Solution: w1d3_bo1_un1c0de_s7r1ng */
int phase6(char* input, size_t inputLen) {
    int ret = 0;
    const wchar_t* flag = L"\u24E6\u2460\u24D3\u2462_\u24D1\u24DE\u2460_\u24E4\u24DD\u2460\u24D2\u24EA\u24D3\u24D4_\u24E2\u2466\u24E1\u2460\u24DD\u24D6";
    wchar_t* answer = (wchar_t*)calloc(inputLen, sizeof(wchar_t));
    for (int ii = 0; ii < inputLen; ii++) {
        answer[ii] = (wchar_t)input[ii];
        if (answer[ii] >= 'a' && answer[ii] <= 'z') {
            answer[ii] = (answer[ii] - 'a') + 0x24D0;
        } else if (answer[ii] >= '1' && answer[ii] <= '9') {
            answer[ii] = (answer[ii] - '1') + 0x2460;
        } else if (answer[ii] == '0') {
            answer[ii] = (answer[ii] - '0') + 0x24EA;
        }

        ret |= !(answer[ii] == flag[ii]);
    }
    
    return ret || !(inputLen == 23);
}

void func7(char* input, size_t inputLen, char* result) {
    /* Credit: https://www.ece.iastate.edu/~alexs/classes/2012_Fall_185/midterm2/Lab_v1/05_Look_and_Say_Sequence.c */
    char prev = input[0];   //The previous character
	int count = 1;          //The count in the current chain
	int i, j = 0;           
	for(i=1; i < inputLen; i++){
		if(input[i] == prev){
			count++;   //If the chain is unbroken, increment the count
		} else {
			//If the chain breaks, store the count and digit in result and reset count
			result[j++] = count + '0';
			result[j++] = prev;
			count = 1;
		}
	
		//Set prev to be the current digit
		prev = input[i];
	}	

	//Handle the last digit using the current value of count and prev
	result[j++] = count + '0';
	result[j++] = prev;
}

/* Solution: 1211_312211_1113213211 */
int phase7(char* input, size_t inputLen) {
    char input1[512] = {'\0'};
    char input2[512] = {'\0'};
    char input3[512] = {'\0'};
    char result[1024] = {'\0'};
    char nothing = 0;

    char* expected[] = {"111221", "13112221", "31131211131221"};
    if(sscanf(input, "%512[^_]_%512[^_]_%512[^_]%c", input1, input2, input3, &nothing) != 3) {
        return 1;
    }

    func7(input1, strnlen(input1, 512), result);
    if(strncmp(result, expected[0], strnlen(result, 512))) {
        return 1;
    }
    memset(result, 0, 1024);

    func7(input2, strnlen(input2, 512), result);
    if(strncmp(result, expected[1], strnlen(result, 512))) {
        return 1;
    }
    memset(result, 0, 1024);

    func7(input3, strnlen(input3, 512), result);
    if(strncmp(result, expected[2], strnlen(result, 512))) {
        return 1;
    }
    memset(result, 0, 1024);

    return 0;
}

struct stru8 {
    char data;
    struct stru8* next;
    struct stru8* prev;
};

void func8_1(char data, struct stru8** head) {
    struct stru8* node = (struct stru8*)malloc(sizeof(struct stru8));
    node->data = data;
    node->next = NULL;
    node->prev = NULL;

    if(*head == NULL) {
        *head = node;
    } else {
        struct stru8* itr = *head;
        while (itr->next) {
            itr = itr->next;
        }
        itr->next = node;
        node->prev = itr;
    }
}

int func8_2(char * flag, struct stru8* head) {
    struct stru8* itr = head;
    int i = 0;
    while(itr) {
        if (itr->prev) {
            if(flag[i] != (itr->prev->data ^ i)) {
                return 1;
            }
            i++;
        }
        if (flag[i] != (itr->data ^ i)) {
            return 1;
        }
        i++;
        if (itr->next) {
            if(flag[i] != (itr->next->data ^ i)) {
                return 1;
            }
            i++;
        }
        itr = itr->next;
    }
    return 0;
}

void func8_3(struct stru8* head) {
    struct stru8* itr = head;
    struct stru8* n;
    while(itr) {
        n = itr->next;
        free(itr);
        itr = n;
    }
}

/* Solution: L1nk3D_tH3_l1sTs */
int phase8(char* input, size_t inputLen) {
    char* flag = "L0N2j4hlfb9`?I=KOUMgKa^cP*R(C.As\x7fM\x13O\x15V\x17T|Z~Xx^";
    struct stru8* node = NULL;
    for (int ii = 0; ii < inputLen; ii++) {
        func8_1(input[ii], &node);
    }
    int ret = func8_2(flag, node);
    func8_3(node);


    return ret || !(inputLen == 16);
}

/* Solution: H1diNG_L0tS_oF_C0d3_iN_4rRaY5 */
int phase9(char* input, size_t inputLen) {
    int ret = 0;
    int key = b.e;
    unsigned char code[] = {0x8c,0x1f,0x53,0xe0,0x76,0x3a,0x25,0xb4,0x3a,0x25,0xd6,0xb8,0x25,0xf6,0x48,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x17,0x30,0xd8,0xc0,0x3a,0x2d,0x36,0xb8,0x30,0xd8,0x47,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0xb,0x30,0xd8,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x13,0x30,0xd8,0xcd,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0xc0,0x30,0xd8,0x4c,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x7b,0x30,0xd8,0x81,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x1b,0x30,0xd8,0xc9,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x67,0x30,0xd8,0x4a,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x2f,0x30,0xd8,0xb,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0xf,0x30,0xd8,0x77,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x23,0x30,0xd8,0xc4,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x77,0x30,0xd8,0x1,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x3,0x30,0xd8,0xcc,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x73,0x30,0xd8,0xcd,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0xcc,0x30,0xd8,0x80,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x3b,0x30,0xd8,0x4a,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x7,0x30,0xd8,0xcd,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x6f,0x30,0xd8,0x58,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x37,0x30,0xd8,0x7,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x3f,0x30,0xd8,0x81,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x1f,0x30,0xd8,0x83,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0xc8,0x30,0xd8,0x88,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x27,0x30,0xd8,0xcd,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0xc4,0x30,0xd8,0x4e,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x33,0x30,0xd8,0xcd,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x6b,0x30,0xd8,0x2,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x7f,0x30,0xd8,0xc3,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x2b,0x30,0xd8,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xce,0xd9,0x63,0x30,0xd8,0xb,0x3c,0x36,0xf8,0xd8,0xd8,0xd8,0xd8,0xac,0xe6,0x2d,0x36,0xf8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0xd8,0xce,0x58,0x98,0x39,0x36,0xfc,0x2d,0x36,0xf8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0xd8,0x1f,0xd1,0xd9,0xc5,0x58,0xc8,0x25,0x30,0x1f,0xf1,0x36,0xfc,0xd9,0xb8,0xc8,0x25,0xc5,0x2d,0x36,0xf8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x27,0x10,0x25,0x80,0x39,0x1b,0x2d,0x36,0xf8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0xd8,0x25,0xc1,0x2d,0x36,0x48,0xc4,0x18,0x15,0x3a,0x4f,0x2d,0x36,0xf8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x25,0x20,0x39,0x1b,0xce,0x36,0xf8,0xc4,0xce,0xd6,0xf8,0x6b,0xd2,0xc6,0x3c,0x36,0xe8,0xd8,0xd8,0xd8,0xd8,0xa4,0x85,0xd8,0xd8,0xd8,0x2d,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0x9b,0xf9,0x6b,0xd8,0xd8,0xd8,0xaf,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0x3b,0x2d,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x87,0x10,0x25,0x80,0x39,0x1b,0xf9,0x6b,0xd8,0xd8,0xd8,0xaf,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0x9b,0x2d,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0x3b,0xf9,0x6b,0xd8,0xd8,0xd8,0xaf,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x87,0x10,0x25,0x80,0x39,0x1b,0x2d,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0x9b,0xf9,0x6b,0xd8,0xd8,0xd8,0xaf,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x1f,0xf1,0x3b,0x2d,0x36,0xe8,0x3a,0x4e,0x18,0x3a,0x2d,0x36,0xb8,0x3a,0xc4,0x18,0x87,0x10,0x25,0x80,0x39,0x1b,0xce,0x36,0xe8,0xc4,0xce,0xd6,0xe8,0x17,0x1f,0x11,0x36,0xdc,0xdc,0xdc,0x19,0x19,0x56,0xcd,};

    char* page = valloc(sizeof(code)); 

    for(int i = 0; i < sizeof(code); i++) {
        //key = key && code[i]+1;
        code[i] ^= 0x37;
        uint8_t lower2 = code[i] & 0x03;
        code[i] = (lower2 << 6) | (code[i] >> 2);
        page[i] = (code[i] + 0x05);
        //code[i] = key || 1;
    }

    mprotect(page, sizeof(code), PROT_EXEC | PROT_WRITE);

    hfunc func = (hfunc)page;

    char flag[50] = {'\0'};

    func(flag, key);

    //int len = 0;
    char* itrF = flag;
    char* itrA = input;
    while(*itrF != '\0' && *itrA != '\0') {
        if(*itrF != *itrA) {
            ret = 1;
            break;
        }
        itrF++;
        itrA++;
    }

    if(*itrF != '\0') ret = 1;

    //memset(page, 0, sysconf(_SC_PAGESIZE));
    free(page);
    return ret;
}

void phasePass(int round) {
    int r = rand() % 6;
    char* msg = (char*)calloc(100, sizeof(char));

    switch(r) {
    case 0:
        sprintf(msg, "Defused phase %d", round);
        break;
    case 1:
        sprintf(msg, "All clear!");
        break;
    case 2:
        sprintf(msg, "Phase %d locked down", round);
        break;
    case 3:
        sprintf(msg, "You did it!!");
        break;
    case 4:
        sprintf(msg, "Onwards to phase %d!", round+1);
        break; 
    default:
        sprintf(msg, "Nice work, but can you defeat phase %d?", (rand() % (NUM_PHASES-round+1) + (round+1)));
        break;
    }
    printf(GREEN "%s\n" RESET, msg);
    free(msg);
}

void phaseFail(int round) {
    int r = rand() % 11;
    char* msg = (char*)calloc(160, sizeof(char));

    switch(r) {
    case 0:
        sprintf(msg, "Round %d EXPLODED!", round);
        break;
    case 1:
        sprintf(msg, "Boom... oops :/");
        break;
    case 2:
        sprintf(msg, "Not quite...");
        break;
    case 3:
        sprintf(msg, "Psst... that's the answer to phase %d!", (rand() % (NUM_PHASES-round+1) + (round+1)));
        break;
    case 4:
        sprintf(msg, "oof");
        break;
    case 5:
        sprintf(msg, "Would you look at that!? The binary bomb went off");
        break;
    case 6:
        sprintf(msg, "Better luck on phase %d", round+1);
        break;
    case 7:
        sprintf(msg, "So close, but yet, so far...");
        break;
    case 8:
        sprintf(msg, "Kaboom goes phase %d!", round);
        break;
    case 9:
        sprintf(msg, "      _.__,_._\n    (_ '(`)_ .__)\n  ( ( (   ) `) ) _)\n (__(_ (_ . _)_),__)\n   `~~`\\ ' . /`~~`\n        ;   ;\n        /   \\\n ______/_ __ \\______");
        break;
    default:
        sprintf(msg, "3... 2... 1...");
        break;
    }
    printf(RED "%s\n" RESET, msg);
    free(msg);
}

void explodeHiss(void) {
    attron(COLOR_PAIR(NC_COUNTDOWN_RED));
    printw("HHHHHHHHH     HHHHHHHHH  iiii                                                  \n");
    printw("H:::::::H     H:::::::H i::::i                                                 \n");
    printw("H:::::::H     H:::::::H  iiii                                                  \n");
    printw("HH::::::H     H::::::HH                                                        \n");
    printw("  H:::::H     H:::::H  iiiiiii     ssssssssss      ssssssssss      ssssssssss  \n");
    printw("  H:::::H     H:::::H  i:::::i   ss::::::::::s   ss::::::::::s   ss::::::::::s \n");
    printw("  H::::::HHHHH::::::H   i::::i ss::::::ss:::::sss::::::ss::::::sss:::::ss:::::s\n");
    printw("  H:::::::::::::::::H   i::::i  s:::::s  ssssss s:::::s  ssssss s:::::s  sssss \n");
    printw("  H::::::HHHHH::::::H   i::::i    s::::::s        s::::::s        s::::::s     \n");
    printw("  H:::::H     H:::::H   i::::i       s::::::s        s::::::s        s::::::s  \n");
    printw("  H:::::H     H:::::H   i::::i ssssss   s:::::sssssss   s:::::sssssss   s::::s \n");
    printw("HH::::::H     H::::::HHi::::::is:::::ssss::::::s:::::ssss::::::s:::::ssss:::::s\n");
    printw("H:::::::H     H:::::::Hi::::::i s:::::::::::ss  s:::::::::::ss  s:::::::::::s  \n");
    rprintw("HHHHHHHHH     HHHHHHHHHiiiiiiii  sssssssssss     sssssssssss     sssssssssss   \n");
    attroff(COLOR_PAIR(NC_COUNTDOWN_RED));
}

void explodeThree(void) {
    printw("        333333333333333                                                        \n");
    printw("       3:::::::::::::::33                           /@&            @@@@        \n");
    printw("       3::::::33333::::::3                    @  #@@    @@@       @  #@&       \n");
    printw("       3333333     3:::::3                 .,@@@@@@@#      @@      @//#        \n");
    printw("                   3:::::3          @@@@#(@@@@@@@@@@@@      (@@    ,@@         \n");
    printw("                   3:::::3       ,@@ @@@@@@@@@@@@@@@@@         @@@@#           \n");
    printw("           33333333:::::3       @@ @@@@@@@@@@@@@@@@@@@@@                       \n");
    printw("           3:::::::::::3       @@ @@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("           33333333:::::3      @@/@@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("                   3:::::3     @@@@@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("                   3:::::3     @@@@@@@@@@@@@@@@@@@@@@@@@/                      \n");
    printw("                   3:::::3      &@@@@@@@@@@@@@@@@@@@@@@                        \n");
    printw("       3333333     3:::::3        @@@@@@@@@@@@@@@@@@@(                         \n");
    printw("       3::::::33333::::::3           *@@@@@@@@@@@@                             \n");
    printw("       3:::::::::::::::33                                                      \n");
    rprintw("        333333333333333                                                        \n");
    move(14, 0);
}

void explodeTwo(void) {
    printw("        222222222222222                                                        \n");
    printw("       2:::::::::::::::22                           /@&      @@@@              \n");     
    printw("       2::::::222222:::::2                    @  #@@    @@@ @  #@&             \n");
    printw("       2222222     2:::::2                 .,@@@@@@@#      @ @//# @            \n");
    printw("                   2:::::2          @@@@#(@@@@@@@@@@@@       ,@@               \n");
    printw("                   2:::::2       ,@@ @@@@@@@@@@@@@@@@@                         \n");
    printw("                2222::::2       @@ @@@@@@@@@@@@@@@@@@@@@                       \n");
    printw("           22222::::::22       @@ @@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("         22::::::::222         @@/@@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("        2:::::22222            @@@@@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("       2:::::2                 @@@@@@@@@@@@@@@@@@@@@@@@@/                      \n");
    printw("       2:::::2                  &@@@@@@@@@@@@@@@@@@@@@@                        \n");
    printw("       2:::::2       222222       @@@@@@@@@@@@@@@@@@@(                         \n");
    printw("       2::::::2222222:::::2          *@@@@@@@@@@@@                             \n");
    printw("       2::::::::::::::::::2                                                    \n");
    rprintw("       22222222222222222222                                                    \n");
    move(14, 0);
}

void explodeOne(void) {
    printw("         1111111                                                               \n");
    printw("        1::::::1                           **@, #/@&) **                       \n");
    printw("       1:::::::1                             (@  #@@// *@                      \n");
    printw("       111:::::1                           .,@@@@@@@#                          \n");
    printw("          1::::1                    @@@@#(@@@@@@@@@@@@                         \n");
    printw("          1::::1                 ,@@ @@@@@@@@@@@@@@@@@                         \n");
    printw("          1::::1                @@ @@@@@@@@@@@@@@@@@@@@@                       \n");
    printw("          1::::l               @@ @@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("          1::::l               @@/@@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("          1::::l               @@@@@@@@@@@@@@@@@@@@@@@@@@                      \n");
    printw("          1::::l               @@@@@@@@@@@@@@@@@@@@@@@@@/                      \n");
    printw("          1::::l                &@@@@@@@@@@@@@@@@@@@@@@                        \n");
    printw("       111::::::111               @@@@@@@@@@@@@@@@@@@(                         \n");
    printw("       1::::::::::1                  *@@@@@@@@@@@@                             \n");
    printw("       1::::::::::1                                                            \n");
    rprintw("       111111111111                                                            \n");
    move(14, 0);
}

void explodeZero(void) {
    printw("            000000000                   @          #                           \n"); 
    printw("          00:::::::::00             .                               $$         \n");
    printw("        00:::::::::::::00   .,     .,, #            #             $$$          \n");
    printw("       0:::::::000:::::::0             ,./#     #   &           (&             \n");
    printw("       0::::::0   0::::::0                ,,,,,,,&  .,,.,.                     \n");
    printw("       0:::::0     0:::::0    $$$$     ,,,,,$,,**/,,*,,,,,,,  $                \n");
    printw("       0:::::0     0:::::0      ,$   #,.,..,$(.,***//./.&..,,                  \n");
    printw("       0:::::0 000 0:::::0    &&     ...$&&,,***,,***((((./(,**,               \n");
    printw("       0:::::0 000 0:::::0          ,,,,,,///////**********,,$,,,,    $        \n");
    printw("       0:::::0     0:::::0  ,      .,,,,$(&(((((((///////&&&&&&&...            \n");
    printw("       0:::::0     0:::::0         ..$,,##(#(///********/(##$#,,,. &           \n");
    printw("       0::::::0   0::::::0     &&&, $*. ##(((**********//((#$#....             \n");
    printw("       0:::::::000:::::::0     .&&&&   #/,(,,***,.,&&*///(  .$....             \n");
    printw("        00:::::::::::::00   .        #  (...*/..,..,*...((    $&(              \n");
    printw("          00:::::::::00            &#,  @(.*. ..   *      (                    \n");
    rprintw("            000000000     ,.        .                       (                  \n");
}

void countdown(void) {
    struct timespec delay = {
        .tv_sec = 0,                /* seconds */
        .tv_nsec = 250000000L       /* nanoseconds */
    };

    for(int ii = 3; ii > 0; ii--) {
        char* colors[] = {YELLOW, GREEN, BLUE};
        printf("%s%d ", colors[ii-1], ii);
        fflush(stdout);
        if(nanosleep(&delay, NULL)) {
             continue;
        }

        for(int jj = 0; jj < 3; jj++) {
            printf(".");
            fflush(stdout);
            if(nanosleep(&delay, NULL)) {
                continue;
            }
        }
        printf("\b\b\b\b\b\b\b\b" RESET);
        fflush(stdout);
    }
    printf(RED "0 Boom!\n" RESET);
}

void explode() {
    efunc explodePhases[] = {explodeThree, explodeTwo, explodeOne, explodeZero};
    struct timespec delay = {
        .tv_sec = 1,       /* seconds */
        .tv_nsec = 0       /* nanoseconds */
    };

    initscr();
    cbreak();

    if(LINES < 30 || COLS < 80) {
        countdown();
    } else {
        move(0, 0);
        start_color();
        init_pair(NC_COUNTDOWN_RED, COLOR_RED, COLOR_BLACK);
        init_pair(NC_BOMB_ANIMATION, COLOR_YELLOW, COLOR_BLACK);

        explodeHiss();
        attron(COLOR_PAIR(NC_BOMB_ANIMATION));
        for(int ii = 0; ii < NUM_EXPLODE_PHASES; ii++) {
            explodePhases[ii]();
            if(nanosleep(&delay, NULL)) {
                continue;
            }
            fflush(stdout);
        }
        attroff(COLOR_PAIR(NC_BOMB_ANIMATION));
    }
    endwin();
}

void help(void) {
    initscr();
    cbreak();
    move(0,0);

    printw("Welcome to the Binary Bomb - Dawg Edition!\n");
    printw("A binary bomb is a series of small RE challenges, increasing in difficulty each stage.\n");
    printw("Each stage will prompt you for an input. If you are correct, the flag will be displayed.\n");
    printw("Once you solve a phase, you can store the solution in a text file and use that file to automatically answer phases. \nUsage: ./dawg_bbomb [flag_file.txt]\n");
    printw("The flag file must be in the format: 1 flag per line with a newline ending\n");
    printw("----\nphAse1_Fl4g\npHA5e2_FLag\nSKIP\n\nphaS35_Fl4g\n");
    printw("%s\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b", helpstr);
    printw("----\n");
    printw("If you want to skip a phase, answer the prompt with SKIP.\n");
    printw("Good luck!  Press any key to continue... ");
    refresh();

    char c;
    scanf("%c", &c);

    endwin();
}

void stripEOL(char* input, size_t* newLen, size_t maxLen) {
    char* i = input;
    *newLen = 0;
    while(i && *newLen < maxLen) {
        if(*i == '\n' || *i == '\r' || *i == '\0') {
            *i = '\0';
            break;
        }
        i++;
        (*newLen)++;
    }
}

void handler(int sigNum) {
    printf(RED "\nThought you could escape that easily?\n" RESET);
    explode();
    CONTINUE_RUNNING = 0;
}

int main(int argc, char* argv[]) {
    /* Setup */
    srand(time(0));
    setlocale(LC_ALL, "");
    struct sigaction sa;
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, 0);

    FILE* flagFile = 0;

    if(argc > 2) {
        fprintf(stderr, "Usage: %s [flag_file.txt]\n", argv[0]);
        exit(-1);
    } else if(argc == 2) {
        flagFile = fopen(argv[1], "r");
        if(!flagFile) {
            fprintf(stderr, "Could not open %s for reading. Exiting.\n", argv[1]);
            exit(-2);
        }
    }

    /* Variables */
    pfunc phases[] = {phase1, phase2, phase3, phase4, phase5, phase6, phase7, phase8, phase9};
    int round = 1;
    int passed = 0;
    char* input = NULL;
    char* inputStore = NULL;
    size_t buffLen = 256;
    size_t inputLen = 0;

    printf("Welcome to the DawgCTF Binary Bomb!\n");
    printf("Type HELP for help.");

    while(CONTINUE_RUNNING && round <= NUM_PHASES) {
        inputLen = 0;
        printf(YELLOW "\n%s\n" RESET, PROMPTS[round-1]);
        printf("Enter round %d input: ", round);
        if(flagFile && !feof(flagFile)) {
            inputLen = getline(&input, &buffLen, flagFile);
            stripEOL(input, &inputLen, buffLen);
        }

        if(inputLen < 1) {
            inputLen = getline(&input, &buffLen, stdin);
            stripEOL(input, &inputLen, buffLen);
        } else {
            printf("%s\n", input);
        }

        inputStore = (char*)realloc(inputStore, sizeof(char)*inputLen+1);
        strncpy(inputStore, input, inputLen+1);

        if(inputLen < 0) {
            break;
        }

        if(inputLen == 0) {
            continue;
        }

        if(!strncmp(input, "SKIP", inputLen)) {
            printf(RED "Skipping phase %d...\n" RESET, round);
            round++;
            continue;
        }
        
        if(!strncmp(input, "HELP", inputLen)) {
            help();
            continue;
        }

        if(!phases[round-1](input, inputLen)) {
            phasePass(round);
            printf(MAGENTA "Flag: DawgCTF{%s}\n" RESET, inputStore);
            passed++;
            round++;
        } else {
            phaseFail(round);
        }
    }

    if(input) {
        free(input);
    }

    if(inputStore) {
        free(inputStore);
    }

    if(flagFile) {
        fclose(flagFile);
    }

    if(passed == NUM_PHASES) {
        printf("\nCongratulations! You defused the Binary Bomb - Dawg Edition!\n");
    } else {
        printf("\nYou've made it to the end, but %d/%d phases still remain active!\n", (NUM_PHASES-passed), NUM_PHASES);
    }

    return 0;
}
