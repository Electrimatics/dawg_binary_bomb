CXX := gcc
FLAGS := -Wall
LIBS := ncurses

dawg_bbomb: dawg_bbomb.c
	$(CXX) $(FLAGS) $^ -o $@ $(LIBS:%=-l%)
	python3 postprocess.py dawg_bbomb

debug: dawg_bbomb.c
	$(CXX) $(FLAGS) -g $^ -o dawg_bbomb_$@ $(LIBS:%=-l%)

valgrind:
	valgrind --leak-check=full --show-leak-kinds=all ./dawg_bbomb

