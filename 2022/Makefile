CXX := gcc
FLAGS := -Wall
LIBS := ncurses

dawg_bbomb: dawg_bbomb.c
	$(CXX) $(FLAGS) $^ -o $@ $(LIBS:%=-l%)

debug: dawg_bbomb.c
	$(CXX) $(FLAGS) -g $^ -o dawg_bbomb_$@ $(LIBS:%=-l%)

valgrind:
	valgrind --leak-check=full --show-leak-kinds=all ./dawg_bbomb

