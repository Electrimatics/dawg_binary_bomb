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
const int NUM_PHASES = 1;

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

int phase1(char* input, size_t inputLen) {
    return 0;
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
        sprintf(msg, "Nice work, but can you defeat phase %d!", rand() % NUM_PHASES + round + 1);
        break;
    }
    printf("%s\n", msg);
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
        sprintf(msg, "Psst... that's the answer to phase %d!", rand() % NUM_PHASES+1);
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
        sprintf(msg, RED "      _.__,_._\n    (_ '(`)_ .__)\n  ( ( (   ) `) ) _)\n (__(_ (_ . _)_),__)\n   `~~`\\ ' . /`~~`\n        ;   ;\n        /   \\\n ______/_ __ \\______" RESET);
        break;
    default:
        sprintf(msg, "3... 2... 1...");
        break;
    }
    printf("%s\n", msg);
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
    start_color();
    init_pair(NC_COUNTDOWN_RED, COLOR_RED, COLOR_BLACK);
    init_pair(NC_BOMB_ANIMATION, COLOR_YELLOW, COLOR_BLACK);

    if(LINES < 30 || COLS < 80) {
        countdown();
    } else {
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

void sigHandler(int sigNum) {
    printf(RED "\nThought you could escape that easily?\n" RESET);
    explode();
    ungetc('\n', stdin);
    CONTINUE_RUNNING = 0;
}

int main(int argc, char* argv[]) {

    signal(SIGINT, sigHandler);

    printf("Welcome to the DawgCTF Binary Bomb!\n");

    pfunc phases[] = {phase1};
    int round = 1;
    int passed = 0;
    char* input = NULL;
    size_t buffLen = 0;
    size_t inputLen = 0;

    while(CONTINUE_RUNNING && round <= NUM_PHASES) {
        inputLen = getInput(&input, &buffLen, "%s");
        if(!strncmp(input, "SKIP\n", inputLen)) {
            printf(GREEN "Skipping phase %d...\n" RESET, round);
            round++;
            continue;
        }

        if(phases[round-1](input, inputLen)) {
            phasePass(round);
            passed++;
            round++;
        } else {
            phaseFail(round);
        }
    }

    free(input);

    return 0;
}
