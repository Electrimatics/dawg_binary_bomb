#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <time.h>
//#include <bits/stdc++.h>
//#include <math.h>

/* Constants */
#define INPUT_LEN 40
#define NUM_PHASES 8

//https://stackoverflow.com/questions/25410690/scanf-variable-length-specifier
#define STR2(x) #x
#define STR(X) STR2(X)

typedef char* (*hfunc)(char*, int);
struct D {
    int p;
};
struct D d = { .p = 0};

char seed[INPUT_LEN];
int total = 0;

/* Phases */
int phase1(char* input);

int phase2(char* input);

int phase3(char* input);
char* func3_1(char* c);
char* func3_2(char* c);

int phase4(char* input);
long long func4(int i);

int phase5(char* input);
int func5(int i);

int phase6(char* input);

int phase7(char* input);

/*
int phase8(char* input);
struct stru8* func8_1(char data, struct stru8* node);
void func8_2(struct stru8* node, char* sol, int* i);
void func8_3(struct stru8* node, char* sol, int* i);
void func8_4(struct stru8* node);
*/

int phase8(char* input);

void defuse(int t);
void success();
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
        perror("ERROR");
        exit(EXIT_FAILURE);
    }

    __cxa_initialize((uintptr_t) __libc_csu_pre_entry);

    __asm volatile("__libc_csu_pre_entry:\n");
    if(ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        srand(time(NULL));
        d.p=(rand()%16)+1;
    }
    seed[0] = 'D';
    seed[1] = 'a';
    seed[2] = 's';
    seed[3] = 'h';
    seed[4] = '_';
    seed[5] = '0';
    seed[6] = 'F';
    seed[7] = '_';
    seed[8] = 'C';
    seed[9] = 'i';
    seed[10] = 'n';
    seed[11] = 'N';
    seed[12] = '4';
    seed[13] = 'M';
    seed[14] = '0';
    seed[15] = 'n';
    seed[16] = '\0';
    __asm volatile("__libc_csu_post_entry:\n");

    __cxa_initialize((uintptr_t) __libc_csu_pre_entry);
}

void getInput(int phase, char* tokenstring, const char* format, ...) {
    printf("Phase %d answer: ", phase);

    //scanf (and cousins) are not for reading, they are for parsing input
    //scanf (") stops when it hits white space and does not include the \n
    //"%[^\n] to include spaces (I think)"
    //https://www.thetopsites.net/article/50077771.shtml

    if(*tokenstring == '\0' || *tokenstring == '\n') {
        fgets(tokenstring, INPUT_LEN, stdin);
        if(strchr(tokenstring, '\n') == NULL) {
            printf("Truncating input to maximum allowed answer size (%d)\n", INPUT_LEN);
            //https://www.thetopsites.net/article/50077771.shtml
            scanf("%*[^\n]");
            scanf("%*c");
        }
    } else {
        printf("%s", tokenstring);
    }

    //https://www.tutorialspoint.com/cprogramming/c_variable_arguments.htm
    //https://www.cplusplus.com/reference/cstdio/vscanf/
    va_list args;
    va_start(args, format);
    vsscanf(tokenstring, format, args);
    va_end(args);
}

int phase1(char* input) {
    //Solution: Gr4nDmAs_S3cr37e_Rec1pE
    printf("\nStarting off easy... reversing things is fun! (Wrap all flags in DawgCTF{} when submitting to the scoreboard)\n");
    int ret = 1;

    char* flag = "Gr4nDmAs_S3cr37_Rec1pE";
    char* answer = calloc(INPUT_LEN+1, sizeof(char));
    getInput(1, input, "%s", answer);

    int i = 0;
    int len = strlen(answer);
    for(; i < strlen(flag) && i < strlen(answer); i++) {
        if(flag[i] != answer[i]) {
            ret = 0;
        }
    }

    if(i != strlen(flag)) ret = 0;

    free(answer);
    return ret;
}

int phase2(char* input) {
    //Solution: T0ny_W4s_H3re
    printf("\nCan you help me find my lost key so I can read my string?\n");

    int ret = 1;
    char* flag = "S7i~XP3tXO4ub";
    char* answer = calloc(INPUT_LEN+1, sizeof(char));
    getInput(2, input, "%s", answer);

    int i = 0;
    for(; i < strlen(flag) && i < strlen(answer); i++) {
        if(flag[i] != (answer[i] ^ 0x7)) {
            ret = 0;
        }
    }

    if(i != strlen(flag)) ret = 0;

    free(answer);
    return ret;
}


int phase3(char* input) {
    //Solution: oN3_P0unD_oF_Fl0uR
    printf("\nReflections? Rotations? Translations? This is starting to sound like geometry...\n");
    
    char* flag = "3pb0r_92\"03$0$J_9t";
    char* answer = calloc(INPUT_LEN+1, sizeof(char));
    getInput(3, input, "%s", answer);

    char* itr = answer;
    while(*itr != '\0') {
        *itr = *func3_1(itr);
        *itr = *func3_2(itr);
        itr++;
    }
    
    int ret = !strcmp(answer, flag);

    free(answer);
    return ret;
}

char* func3_1(char* c) {
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

char* func3_2(char* c) {
    if(*c >= '!' && *c <= '~') {
        *c -= 47;
        *c += 94*(*c < '!');
    }
    return c;
}

//!
int phase4(char* input) {
    //Solution: 7 17 29 43
    //Flag: input_application_display_uninstall
    printf("\nThis is the phase you have been waiting for... one may say it's the golden stage!\n");
    printf("Let's switch things up! Numerical inputs map to line numbers in cs_words.txt, and each word is separated by a '_' (if the phase's solution is 4 5, the flag would be DawgCTF{online_program})\n");

    int ret = 1;
    long long flag[] = {13, 1597, 514229, 433494437};
    //int factor = func4(10);

    int* indexes = calloc(4, sizeof(int));
    getInput(4, input, "%d%d%d%d", &indexes[0], &indexes[1], &indexes[2], &indexes[3]);

    for(int i = 0; i < 4; i++) {
        if(flag[i] != func4(indexes[i])) {
            ret = 0;
        }
    }

    free(indexes);
    return ret;
}

long long func4(int seq) {
    if(seq > 50) return 0;
    if(seq <= 0) return 0;
    if(seq == 1) return 1;
    else return func4(seq-1) + func4(seq-2);
}

int phase5(char* input) {
    //Solution: 283 293 307 311
    //Flag: overhead_cyber_foreground_reference
    printf("\nAre you really, really ready and excited for this stage?\n");

    int ret = 1;
    int* primes = calloc(4, sizeof(int));
    getInput(5, input, "%d%d%d%d", &primes[0], &primes[1], &primes[2], &primes[3]);

    int sum = 0;
    if(primes[0] < 282) ret = 0;
    for(int i = 0; i < 4; i++) {
        if(i > 0 && (primes[i-1] > primes[i] || primes[i-1] < (primes[i]-15))) {
            ret = 0;
        }
        ret = ret & func5(primes[i]);
        sum += primes[i];
    }

    if(sum != 1194) ret = 0;

    free(primes);
    return ret;
}

int func5(int n) {
    if(n % 2 == 0 || n <= 1) return 0;
    for(int i = 3; i < n/2; i+=2) {
        if(n % i == 0) {
            return 0;
        }
    }
    return 1;
}

//!
int phase6(char* input) {
    //Solution: H4lf_P0unD_oF_suG4r
    printf("\nOh no... I lost the key to my string again :(\n");

    int ret = 1;
    //char flag[] = {0x48, 0x34, 0x6c, 0x66, 0x5f, 0x50, 0x30, 0x75, 0x6e, 0x44, 0x5f, 0x6f, 0x46, 0x5f, 0x73, 0x75, 0x47, 0x34, 0x72, 0x0};
    char flag[] = {0x84, 0x43, 0xc6, 0x66, 0xf5, 0x05, 0x03, 0x57, 0xe6, 0x44, 0xf5, 0xf6, 0x64, 0xf5, 0x37, 0x57, 0x74, 0x43, 0x27, 0x0};
                 //0x48, 0x34, 0x6c, 0x66, 0x5f, 0x50, 0x30, 0x75, 0x6e, 0x44, 0x5f, 0x6f, 0x46, 0x5f, 0x73, 0x75, 0x47, 0x34, 0x72
    char* answer = calloc(INPUT_LEN+1, sizeof(char));
    getInput(6, input, "%s", answer);

    int i = 0;
    for(; i < strlen(flag) && i < strlen(answer); i++) {
        uint8_t half = (answer[i] & 0xf0);
        answer[i] = (answer[i] << 4) | (half >> 4);
        //answer[i] = answer[i] ^ 0x64;
        if(answer[i] != flag[i]) {
            ret = 0;
        }
    }

    if(i != strlen(flag)) ret = 0;

    free(answer);
    return ret;
}

int phase7(char* input) {
    //Solution: 113 197 337
    //Flag: build_serial_account
    printf("\nAt least we can say our code is resuable\n");

    int ret = 1;
    //https://stackoverflow.com/questions/36890624/malloc-a-2d-array-in-c
    char** answer = malloc(3*sizeof(char*));
    for(int i = 0; i < 3; i++) answer[i] = calloc(INPUT_LEN+1, sizeof(char));
    getInput(7, input, "%s%s%s", answer[0], answer[1], answer[2]);
    int sum = 0;

    for(int i = 0; i < 3; i++) {
        sum += atoi(answer[i]);
        if(i > 0 && atoi(answer[i-1]) > atoi(answer[i])) ret = 0;
        for(int j = 0; j < 3; j++) {
            if(atoi(answer[i]) < 100) {
                ret = 0;
                break;
            }
            ret = ret & func5(atoi(answer[i]));

            uint8_t lower = answer[i][2];
            answer[i][2] = answer[i][1];
            answer[i][1] = answer[i][0];
            answer[i][0] = lower;
        }
    }

    if(sum != 647) ret = 0;

    for(int i = 0; i < 3; i++) free(answer[i]);
    free(answer);
    return ret;
}

struct stru8 {
    char data;
    struct stru8* left;
    struct stru8* right;
};

/*
int phase8(char* input) {
    //Solution: Spr1nKL3_Of_ChOcoL4Te
    printf("\nGo touch grass!\n");

    char* flaga = "T30G343DDERh_TWT_e_ror";
    char* flagb = "";
    char* answer = calloc(INPUT_LEN+1, sizeof(char));
    char* checka = (char*)calloc(INPUT_LEN+1, sizeof(char));
    char* checkb = (char*)calloc(INPUT_LEN+1, sizeof(char));
    getInput(8, input, "%s", answer);

    struct stru8* root = NULL;
    for(int i = 0; i < strlen(flaga); i++) {
        root = func8_1(answer[i], root);
    }

    int j = 0;
    int k = 0;
    func8_2(root, checka, &j);
    func8_3(root, checkb, &k);
    //int ret = !strcmp(answer, flag);
    printf("%s\n -- ", checka, checkb);
    func8_4(root);

    free(answer);
    free(checka);
    free(checkb);
    int ret = 0;
    return ret;
}

struct stru8* func8_1(char data, struct stru8* node) {
    if(node == NULL) {
        struct stru8* node = (struct stru8*)malloc(sizeof(struct stru8));
        node->data = data;
        node->left = node->right = NULL;
        return node;
    } else if(data < node->data) {
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
    sol[*i] = node->data;
    //printf("%d\n", *i);
    *i = *i+1;
    func8_2(node->left, sol, i);
    func8_2(node->right, sol, i);
}

void func8_3(struct stru8* node, char* sol, int* i) {
    if(node == NULL) {
        return;
    }
    func8_3(node->left, sol, i);
    sol[*i] = node->data;
    *i = *i+1;
    func8_3(node->right, sol, i);
}

void func8_4(struct stru8* node) {
    if(node == NULL) {
        return;
    }
    func8_4(node->left);
    func8_4(node->right);
    free(node);
}
*/

int phase8(char* input) {
    //Solution: Spr1nKL3_Of_ChOcoL4Te
    printf("\nWho doesn't <3 arrays?\n");

    int ret = 1;
    int key = d.p;
    unsigned char code[] = {0xbb,0x28,0x64,0xd7,0x41,0xd,0x12,0x83,0xd,0x12,0xe1,0x8f,0x12,0xc1,0x7f,0x1a,0x1,0x7f,0xf9,0xee,0x29,
                            0xe,0x1,0xe7,0x1a,0x1,0x7f,0xf9,0xee,0xbc,0xe,0x1,0xeb,0xd,0x1a,0x1,0x8f,0x7,0xef,0x2d,0xd,0x1a,0x1,
                            0x8f,0x28,0xc6,0xef,0xf9,0xee,0xfb,0x12,0xf6,0xd,0x1a,0x1,0x8f,0xe,0x2c,0x1a,0x1,0x7f,0x22,0x2d,0xad,
                            0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0xf3,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0xf7,0x7,0xef,0x84,0xd,
                            0x1a,0x1,0x8f,0xd,0xf9,0xee,0xf7,0x28,0xc6,0xef,0x12,0xf6,0x12,0x2f,0xf3,0xee,0xf3,0xf6,0xd,0x1a,0x1,
                            0x8f,0xd,0xf9,0xee,0xf7,0xe,0x2c,0x28,0xc6,0x1,0xeb,0x22,0x2d,0xe3,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,
                            0xfb,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0xff,0x7,0xef,0x91,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0xff,
                            0x28,0xc6,0x2c,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0xff,0xf9,0xb7,0x8,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,0xf9,
                            0xee,0x0,0x7,0xef,0x19,0x1a,0x1,0x7f,0x22,0x2d,0x1d,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x4,0xe,0x2c,0xd,
                            0x1a,0x1,0x8f,0xd,0xf9,0xee,0x8,0x7,0xef,0xb8,0x28,0xc6,0x1,0xe7,0x22,0x2d,0x2c,0xd,0x1a,0x1,0x8f,0xd,
                            0xf9,0xee,0xc,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,0x22,0x2d,0x10,0x28,0xc6,0x1,0xe7,0xe,0xf7,0xd,0x1a,0x1,
                            0x8f,0xd,0xf9,0xee,0x14,0x7,0xef,0x48,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x14,0x28,0xc6,0xef,0x12,0xf6,
                            0x28,0xc6,0x1,0xe7,0xf3,0xf6,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x14,0xe,0x2c,0x1a,0x1,0x7f,0x22,0x2d,0x69,
                            0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x18,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x1c,0x7,0xef,0xf8,0xd,
                            0x1a,0x1,0x8f,0xd,0xf9,0xee,0x20,0x7,0xef,0x50,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x20,0x28,0xc6,0xef,0x12,
                            0xf6,0x28,0xc6,0x1,0xe7,0xf3,0xf6,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x20,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,
                            0xf9,0xee,0x24,0x7,0xef,0x29,0x1a,0x1,0x7f,0x22,0x2d,0x79,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x28,0xe,0x2c,
                            0x28,0xc6,0x1,0xe7,0x22,0x2d,0x6c,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x2c,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,
                            0xf9,0xee,0x30,0x7,0xef,0xdc,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x30,0x28,0xc6,0xef,0x22,0x2d,0x2c,0xd,0x1a,
                            0x1,0x8f,0xd,0xf9,0xee,0x30,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,0x22,0x2d,0x34,0x28,0xc6,0x1,0xeb,0xe,0xf7,
                            0x1a,0x1,0x7f,0x22,0x2d,0x3d,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x38,0xe,0x2c,0x1a,0x1,0x7f,0x22,0x2d,0x81,
                            0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x3c,0xe,0x2c,0xd,0x1a,0x1,0x8f,0xd,0xf9,0xee,0x40,0x7,0xef,0xef,0xd,
                            0x1a,0x1,0x8f,0x61,0xfa};
    char* answer = calloc(INPUT_LEN+1, sizeof(char));
    getInput(8, input, "%s", answer);

    char* new_page = valloc(sizeof(code)); 

    for(int i = 0; i < sizeof(code); i++) {
        uint8_t lower2 = code[i] & 0x03;
        key = key && code[i]+1;
        code[i] = (lower2 << 6) | (code[i] >> 2);
        new_page[i] = (code[i] + 0x5);//^ 0x77;
        code[i] = key || 1;
    }

    mprotect(new_page, sizeof(code), PROT_EXEC | PROT_WRITE);

    hfunc func = (hfunc)new_page;

    char f[INPUT_LEN+1];
    char* flag;

    flag = func(f, key);

    int len = 0;
    char* itrF = flag;
    char* itrA = answer;
    while(*itrF != '\0' && *itrA != '\0') {
        if(*itrF != *itrA) {
            ret = 0;
            goto cleanup;
        }
        itrF++;
        itrA++;
    }

    if(*itrF != '\0') ret = 0;

cleanup:
    memset(new_page, 0, sysconf(_SC_PAGESIZE));
    free(new_page);
    free(answer);
    return ret;
}

void defuse(int t) {
    if(t) {
        success();
        total++;
    } else {
        explode();
    }
}

void success() {
    int r = rand() % 6;
    char* msg;

    switch(r) {
    case 0:
        msg = "Defused!";
        break;
    case 1:
        msg = "All clear!";
        break;
    case 2:
        msg = "Phase locked down";
        break;
    case 3:
        msg = "You did it!!";
        break;
    case 4:
        msg = "Onwards!";
        break; 
    default:
        msg = "Nice work!";
        break;
    }
    printf("%s\n", msg);
}

void explode() {
    int r = rand() % 11;
    char* msg;

    switch(r) {
    case 0:
        msg = "EXPLODED!";
        break;
    case 1:
        msg = "Boom... oops :/";
        break;
    case 2:
        msg = "Not quite...";
        break;
    case 3:
        msg = "Psst... that's the answer to phase 8 :)";
        break;
    case 4:
        msg = "oof";
        break;
    case 5:
        msg = "Would you look at that!? The binary bomb went off";
        break;
    case 6:
        msg = "Better luck next time";
        break;
    case 7:
        msg = "So close!";
        break;
    case 8:
        msg = "Kaboom!";
        break;
    case 9:
        msg = "     ___\n   _/  \|\\\\\n  /( )\|  ) )\n (_( (_\| _))\n   \\\|}\|)\|/\n   ( \|)1 )\n  (0\|{ \|1\\)";
        break;
    default:
        msg = "3... 2... 1... boom!";
        break;
    }
    printf("%s\n", msg);
}

void func3_3(void) {
    //Solution: D4sh_0F_CinN4M0n
    int fd = open("/dev/tty", O_RDWR);
    write(fd, seed, 20);

    int a = 5000;
    for(int i = 0; i < a; i++) {
        for(int j = 0; j < a; j++) {}
    }

    write(fd, "\33[2K\r \n", 7);
}

int main(int argc, char* argv[]) {
    srand(time(NULL));

    printf("You can store known flags in a file named 'flag.txt' in the same directory as this binary.\n");
    printf("Enter 1 flag per line, any empty lines will default to user input, and leave 1 empty line after the last flag. An example to store phase 1, 2, and 4's flags:\n");
    printf("----\nphAse1_Fl4g\npHA5e2_FLag\n\nphaS34_Fl4g\n\n----\n");
    printf("(Note: This file must use Unix line endings. If you edit this file on a Windows machine, run 'dos2unix' on the file)\n");

    printf("\nWelcome to the binary bomb! Tick tock...\n");
    printf("To skip a phase, press enter as the phase's input\n");

    FILE* fptr = fopen("flags.txt", "r");
    char flags[NUM_PHASES][INPUT_LEN+1] = {'\0'};
    if(fptr == NULL) {
        printf("Flag file 'flags.txt' not found in this directory - using user input.\n");
    } else {
        for(int i = 0; i < NUM_PHASES; i++) {
            fgets(flags[i], INPUT_LEN, fptr);
            if(strchr(flags[i], '\n') == NULL && strlen(flags[i]) > 0) {
                printf("\nInput length (%d) reached on phase %d flag. Rerun the binary bomb with a smaller input, or if this is the last flag in the file, ensure there is an empty line beneath it (see example above)\n", INPUT_LEN, i+1);
                exit(-1);
            }
        }
        fclose(fptr);
    }

    defuse(phase1(flags[0]));
    defuse(phase2(flags[1]));
    defuse(phase3(flags[2]));
    defuse(phase4(flags[3]));
    defuse(phase5(flags[4]));
    defuse(phase6(flags[5]));
    defuse(phase7(flags[6]));
    //defuse(phase8(flags[7]));
    defuse(phase8(flags[7]));

    if(total == NUM_PHASES) {
        printf("\nCongratulations! You defused the Binary Bomb - Dawg Edition!\n");
    } else {
        printf("\nYou've made it to the end, but some phases still remain active!\n");
    }

    return 0;
}