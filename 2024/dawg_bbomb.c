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
char helpstr[50];
int maxFailPrompt = 10;

/* Explode sequences prototypes */
void countdown(void);
void explode(void);

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
        maxFailPrompt = 11;
    }

    helpstr[0]='0';
    helpstr[1]='h';
    helpstr[2]='_';
    helpstr[3]='n';
    helpstr[4]='O';
    helpstr[5]='_';
    helpstr[6]='Y';
    helpstr[7]='0';
    helpstr[8]='U';
    helpstr[9]='_';
    helpstr[10]='F';
    helpstr[11]='o';
    helpstr[12]='u';
    helpstr[13]='N';
    helpstr[14]='D';
    helpstr[15]='_';
    helpstr[16]='M';
    helpstr[17]='3';
    helpstr[18]='!';

    __asm volatile("__libc_csu_post_entry:\n");

    __cxa_initialize((uintptr_t) __libc_csu_pre_entry);
}

/* Phases */
const int NUM_PHASES = 6;
const char* PROMPTS[] = {
    "Baby's first RE! What is this? This is my _____",
    "Can you help me? I lost the keys to my string and can't read it :(",
    "I've been spun around so much... my head kinda hurts now :/",
    "Slice 'n Dice (strings?)!",
    "It seems I have lost the key again...",
    "Now moving onto big strings!",
    // "Did you find the hidden flag?",
};

/* Solution: My_F1r57_RE_Ch4lLEng3 */
int phase1(char* input, size_t inputLen) {
    char* flag = "My_F1r57_RE_Ch4lLEng3";

    return !strncmp(input, flag, inputLen) && inputLen == strlen(flag);
}

/* Solution: Y0u_FoUND_mY_k3y */
int phase2(char* input, size_t inputLen) {
    char* flag = "H!dNW~D_UN|HNz\"h";

    for(int ii = 0; ii < inputLen; ii++) {
        input[ii] ^= 0x11;
        input[ii] ^= 0x22;
        input[ii] ^= 0x33;
        input[ii] ^= 0x44;
        input[ii] ^= 0x55;
    }

    return !strncmp(input, flag, inputLen) && inputLen == strlen(flag);
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

//TODO:
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

    return !strncmp((char*)uinput, flag, inputLen) && inputLen == strlen(flag);
}

/* Solution: Cu7_mY_5Tr1Ng_iN70_PI3c3s */
int phase4(char* input, size_t inputLen) {
    char flag[] = {0xc1, 0x5d, 0xdc, 0xf5, 0x79, 0x65, 0xf5, 0x5c, 0x15, 0x8d, 0x4c, 0xb1, 0xd9, 0xf5, 0x69, 0xb1, 0xdc, 0x0c, 0xf5, 0x05, 0x61, 0xcc, 0xc9, 0xcc, 0xcd, 0x0};

    for (int ii = 0; ii < inputLen; ii++) {
        uint8_t upper_half = input[ii] >> 4;
        uint8_t lower_half = input[ii] & 0xf;
        
        upper_half = (upper_half >> 2) | ((upper_half & 0x3) << 2);
        lower_half = (lower_half >> 2) | ((lower_half & 0x3) << 2);
        input[ii] = (lower_half << 4) | upper_half;
    }

    return !strncmp(input, flag, inputLen) && inputLen == strlen(flag);
}

//TODO: 
/* Solution: A_m0rE_ComPl3X_X0R_3ncoD1nG */
int phase5(char* input, size_t inputLen) {
    char flag[] = {0x56,0x38,0x4e,0x64,0x3a,0x1d,0x1c,0x4c,0x7d,0x1c,0x73,0x79,0x16,0x16,0x7a,0x4e,0x2d,0x2c,0x13,0x3d,0x0d,0x0b,0x26,0x53,0x4c,0x23,0x0f};

    if(inputLen < 2) {
        return 0;
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

    return !strncmp(input, flag, inputLen) && inputLen == strlen(flag);
}

//TODO:
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

        ret &= answer[ii] == flag[ii];
    }
    
    return ret && inputLen == 23;
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
    int r = rand() % maxFailPrompt;
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
    case 10:
        sprintf(msg, "Not even your debugger could save you from the power of the binary bomb ;)");
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

void handler(int signo) {
    printf(RED "\nThought you could escape that easily?\n" RESET);
    explode();
    CONTINUE_RUNNING = 0;
}

int main(int argc, char* argv[]) {
    /* Setup */
    srand(time(0));
    setlocale(LC_ALL, "");
    struct sigaction act = {0};
    act.sa_handler = &handler;
    sigaction(SIGINT, &act, 0);

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
    pfunc phases[] = {phase1, phase2, phase3, phase4, phase5, phase6};
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

        if(phases[round-1](input, inputLen)) {
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
        printf("But, one secret flag still remains...\n");
    } else {
        printf("\nYou've made it to the end, but %d/%d phases still remain active!\n", (NUM_PHASES-passed), NUM_PHASES);
    }

    return 0;
}
