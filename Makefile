NAME = ntpperf

CPPFLAGS = -D_GNU_SOURCE
CFLAGS = -O2 -Wall -g
LDFLAGS = -lpcap -lm

all: $(NAME)

$(NAME): perf.o sender.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(NAME) *.o
