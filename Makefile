SRCDIR=src
OBJS=jscrypt.o jscexample.o
LIBS=-lcrypto
CFLAGS=-Wall -g

all: demo/jscdemo

demo/jscdemo: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<
