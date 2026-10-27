teatime: teatime.c tea1.h
	gcc teatime.c -o teatime -O3 -march=native -mtune=native -funroll-loops -flto -lpthread

