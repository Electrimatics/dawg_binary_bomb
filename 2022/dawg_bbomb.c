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
char seed[50];


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
        *c ^= 0xc8;
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

    //__cxa_initialize((uintptr_t) __libc_csu_pre_entry);

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

    seed[0] = 'S';
    seed[1] = 'u';
    seed[2] = 'p';
    seed[3] = '3';
    seed[4] = 'R';
    seed[5] = '_';
    seed[6] = 'D';
    seed[7] = 'u';
    seed[8] = 'P';
    seed[9] = 'e';
    seed[10] = 'R';
    seed[11] = '_';
    seed[12] = '5';
    seed[13] = 'e';
    seed[14] = 'c';
    seed[15] = 'R';
    seed[16] = 'e';
    seed[17] = '7';
    seed[18] = '_';
    seed[19] = 'F';
    seed[20] = 'l';
    seed[21] = '4';
    seed[22] = 'g';

    __asm volatile("__libc_csu_post_entry:\n");

    //__cxa_initialize((uintptr_t) __libc_csu_pre_entry);
}

/* Phases */
const int NUM_PHASES = 9;
const char* PROMPTS[] = {
    "Getting things started with stringing characters together...",
    "I encoded my string so no one else could read it... but I lost the key!",
    "I've been spun around so much... my head kinda hurts now :/",
    "I'm feeling good about this one... you might say I'm feeling golden!",
    "It seems I have lost the key again...",
    "This seems familiar, almost like I see it everywhere.",
    "What's the flag now? Could you please say it to me?",
    "I'm going to go out on a limb and say this one might be challenging...",
    "Did you find the bonus flag?",
};

/* Solution: S7r1NgS_4rE_Co0L */
int phase1(char* input, size_t inputLen) {
    char* flag = "S7r1NgS_4rE_Co0L";

    return strncmp(input, flag, inputLen);
}

/* Solution: I5_tH1s_R3verS1BlE_enCryP7i0n */
int phase2(char* input, size_t inputLen) {
    char* flag = "Q-GlP)kGJ+n}jK)Zt]G}v[jaH/q(v";

    for(int ii = 0; ii < inputLen; ii++) {
        input[ii] ^= 0x18;
    }

    return strncmp(input, flag, inputLen);
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

/* Solution: Sp1n_mE_R1gH7_R0Und_B4by */
int phase3(char* input, size_t inputLen) {
    char* flag = "uAS?=1g=tS+w\"=tR3?(=d}&W";
    unsigned char* uinput = (unsigned char*)input;

    for(int ii = 0; ii < inputLen; ii++) {
        func3_2(&uinput[ii], 13);
        func3_1(&uinput[ii]);
        func3_2(&uinput[ii], 25);
        func3_1(&uinput[ii]);
        func3_2(&uinput[ii], 9);
    }

    return strncmp((char*)uinput, flag, inputLen);
}

long long func4(int seq) {
    if(seq > 50) return 0;
    if(seq <= 0) return 0;
    if(seq == 1) return 1;
    else return func4(seq-1) + func4(seq-2);
}

/* Solution: 17_23_29 */
int phase4(char* input, size_t inputLen) {
    int i1, i2, i3;
    char nothing;
    if(sscanf(input, "%d_%d_%d%c", &i1, &i2, &i3, &nothing) != 3) {
        return 1;
    }
    long long expected[] = {1597, 28657, 514229};

    if(func4(i1) != expected[0]) {
        return 1;
    }

    if(func4(i2) != expected[1]) {
        return 1;
    }

    if(func4(i3) != expected[2]) {
        return 1;
    }

    return 0;
}

/* Solution: X0r_3nC1pHerm3nT_c4sCaD1nG */
int phase5(char* input, size_t inputLen) {
    char flag[] = {0x56, 0x38, 0x4e, 0x64, 0x34, 0x33, 0x21, 0x56, 0x46, 0x2d, 0x1a, 0x2b, 0x4c, 0x4f, 0x0e, 0x06, 0x3c, 0x29, 0x50, 0x63, 0x3c, 0x4c, 0x7d, 0x3c, 0x53, 0x79};

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

    return strncmp(input, flag, inputLen);
}

/* Solution: 6_13_9_55_18_4181_28_514229 */
int phase6(char* input, size_t inputLen) {
    int i1, i2, i3, i4, i5, i6, i7, i8;
    char nothing = 0;
    if(sscanf(input, "%d_%d_%d_%d_%d_%d_%d_%d%c", &i1, &i2, &i3, &i4, &i5, &i6, &i7, &i8, &nothing) != 8) {
        return 1;
    }
    float expected[] = {1.625, 1.6176470588235294, 1.618034055727554, 1.6180339887543225};

    if(i1 >= i3 || i3 >= i5 || i5 >= i7) {
        return 1;
    }

    if((float)i2/func4(i1) != expected[0]) {
        return 1;
    }

    if((float)i4/func4(i3) != expected[1]) {
        return 1;
    }

    if((float)i6/func4(i5) != expected[2]) {
        return 1;
    }

    if((float)i8/func4(i7) != expected[3]) {
        return 1;
    }

    return 0;
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
    struct stru8* left;
    struct stru8* right;
};

struct stru8* func8_1(char data, struct stru8* node) {
    if(node == NULL) {
        struct stru8* node = (struct stru8*)malloc(sizeof(struct stru8));
        node->data = data;
        node->left = node->right = NULL;
        return node;
    } else if(data > node->data) {
        node->left = func8_1(data, node->left);
    } else {
        node->right = func8_1(data, node->right);
    }
    return node;
}

void func8_2(struct stru8* node, char* sol, int* i) {
    if(node == NULL) {
        return;
    }
    func8_2(node->left, sol, i);
    sol[*i] = node->data;
    *i = *i+1;
    func8_2(node->right, sol, i);
}

void func8_3(struct stru8* node, char* sol, int* i) {
    if(node == NULL) {
        return;
    }
    sol[*i] = node->data;
    *i = *i+1;
    func8_3(node->left, sol, i);
    func8_3(node->right, sol, i);
}

void func8_4(struct stru8* node, char* sol, int* i) {
    if(node == NULL) {
        return;
    }
    func8_4(node->left, sol, i);
    func8_4(node->right, sol, i);
    sol[*i] = node->data;
    *i = *i+1;
}

void func8_5(struct stru8* node) {
    if(node == NULL) {
        return;
    }
    func8_5(node->left);
    func8_5(node->right);
    free(node);
}

/* Solution: B4cKwArD5_B1n4ry_7REe_1S_a_Tr3E */
int phase8(char* input, size_t inputLen) {
    char* expected[] = {"ywrrrneca_____TSRKEEDBBA7544311", "BcwyrnrreK_a_R_S__TDEE4AB571431", "yrrenrwaT__S_R__EEDKcB75A34114B"};

    char* check1 = (char*)calloc(inputLen+1, sizeof(char));
    strncpy(check1, input, inputLen);

    char* check2 = (char*)calloc(inputLen+1, sizeof(char));
    strncpy(check2, input, inputLen);

    char* check3 = (char*)calloc(inputLen+1, sizeof(char));
    strncpy(check3, input, inputLen);

    struct stru8* root = NULL;
    for(int i = 0; i < strlen(input); i++) {
        root = func8_1(input[i], root);
    }

    int c = 0;
    func8_2(root, check1, &c);
    if(strncmp(check1, expected[0], inputLen)) {
        return 1;
    }

    c = 0;
    func8_3(root, check2, &c);
    if(strncmp(check2, expected[1], inputLen)) {
        return 1;
    }

    c = 0;
    func8_4(root, check3, &c);
    if(strncmp(check3, expected[2], inputLen)) {
        return 1;
    }

    func8_5(root);
    root = 0;

    free(check1);
    free(check2);
    free(check3);

    return 0;
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
    printw("A binary bomb is a series of small RE challenges, typically geared towards beginners.\n");
    printw("This RE challenge is no different, however, the phases do get progressively more difficult.\n");
    printw("Each stage will prompt you for an input. If you are correct, the flag will be displayed.\n");
    printw("Once you solve a phase, you can store the solution in a text file and use that file to automatically answer phases. \nUsage: ./dawg_bbomb [flag_file.txt]\n");
    printw("The flag file must be formatted in the following way, 1 flag per line ending with a newline:\n");
    printw("----\nphAse1_Fl4g\npHA5e2_FLag\nSKIP\n\nphaS35_Fl4g\n");
    printw("%s\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b", seed);
    printw("----\n");
    printw("If you want to skip a phase, answer the prompt with SKIP.\n");
    printw("Happy Reversing!  Press any key to continue... ");
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
