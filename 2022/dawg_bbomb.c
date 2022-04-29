#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <error.h>
#include <ncurses.h>

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

typedef int (*pfunc)(char*, size_t);

/* Explode function pointers */
typedef void (*efunc)(void);
const int NUM_EXPLODE_PHASES = 4;
int CONTINUE_RUNNING = 1;

/**
 * Phase ideas
 * 1.
 * 2.
 * 3.
 * 4.
 * 5.
 * 6.
 */

/* Phase function prototypes */

/* Explode sequences prototypes */
void countdown(void);

/* Utility functions */

size_t getInput(char** input, size_t* buffLen, const char* format, ...);
void explode();

/* Phases */
const int NUM_PHASES = 2;
const char* PROMPTS[] = {
    "Getting things started with stringing characters together...",
    "I encoded by string so not one else could read it... but I lost the key!"
};

/* Solution: S7r1NgS_4rE_Co0L */
int phase1(char* input, size_t inputLen) {
    char* flag = "S7r1NgS_4rE_Co0L";

    return strncmp(input, flag, inputLen);
}

/* Solution: X0r_3nC1pHerm3nT_c4sCaD1nG */
int phase2(char* input, size_t inputLen) {
    char flag[] = {0x79, 0x53, 0x3c, 0x7d, 0x4c, 0x3c, 0x63, 0x50, 0x29, 0x3c, 0x06, 0x0e, 0x4f, 0x4c, 0x2b, 0x1a, 0x2d, 0x46, 0x56, 0x21, 0x33, 0x34, 0x64, 0x4e, 0x38, 0x56};

    if(inputLen < 2) {
        return 1;
    }

    for(int ii = 0; ii < inputLen-1; ii++) {
        input[ii] = input[ii] ^ input[ii+1];
        input[ii] ^= 0x11;
    }

    input[inputLen - 1] ^= 0x11;

    printf("%s\n", input);

    return strncmp(input, flag, inputLen);
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

int phase3(char* input, size_t inputLen) {

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
        sprintf(msg, "Nice work, but can you defeat phase %d!", (rand() % (NUM_PHASES-round+1) + (round+1)));
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

    if(LINES < 30 || COLS < 80) {
        countdown();
    } else {
        initscr();
        cbreak();
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

size_t getInput(char** input, size_t* buffLen, const char* format, ...) {
    /* References:
     * https://www.tutorialspoint.com/cprogramming/c_variable_arguments.htm
     * https://www.cplusplus.com/reference/cstdio/vscanf/
     */
    size_t inputLen = getline(input, buffLen, stdin);

    va_list args;
    va_start(args, format);
    vsscanf(*input, format, args);
    va_end(args);

    return inputLen;
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


    /* Variables */
    pfunc phases[] = {phase1, phase2};
    int round = 1;
    int passed = 0;
    char* input = NULL;
    size_t buffLen = 256;
    size_t inputLen = 0;

    printf("Welcome to the DawgCTF Binary Bomb!\n");

    while(CONTINUE_RUNNING && round <= NUM_PHASES) {
        printf(YELLOW "\n%s\n" RESET, PROMPTS[round-1]);
        printf("Enter round %d input: ", round);
        inputLen = getline(&input, &buffLen, stdin);
        stripEOL(input, &inputLen, buffLen);

        if(inputLen < 0) {
            break;
        }
        
        if(!strncmp(input, "SKIP", inputLen)) {
            printf(RED "Skipping phase %d...\n" RESET, round);
            round++;
            continue;
        }

        if(!phases[round-1](input, inputLen)) {
            phasePass(round);
            printf(MAGENTA "Flag: DawgCTF{%s}\n" RESET, input);
            passed++;
            round++;
        } else {
            phaseFail(round);
        }
    }

    if(input) {
        free(input);
    }

    if(passed == NUM_PHASES) {
        printf("\nCongratulations! You defused the Binary Bomb - Dawg Edition!\n");
    } else {
        printf("\nYou've made it to the end, but some phases still remain active!\n");
    }

    return 0;
}
