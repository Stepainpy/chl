.PHONY: all clean
CC = cc
CFLAGS += -std=c11 -O2 -s
CFLAGS += -Wall -Wextra -pedantic
TARGET = tp
OBJDIR = bin

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,$(OBJDIR)/%.o,$(SRC))

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJDIR):
	mkdir -p $@

clean:
	rm -rf $(TARGET) $(OBJDIR)