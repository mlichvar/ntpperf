NAME = ntpperf

CPPFLAGS = -D_GNU_SOURCE
CFLAGS ?= -O2 -Wall -g
LDFLAGS = -lpcap -lm

ifdef NTPPERF_NTS
CPPFLAGS += -DNTS
CFLAGS += $(shell pkg-config --cflags gnutls)
LDFLAGS += $(shell pkg-config --libs gnutls)
endif

all: $(NAME)

$(NAME): perf.o sender.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(NAME) *.o
