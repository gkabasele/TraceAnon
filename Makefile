CC=g++
CFLAGS= -g
LDFLAGS=-lpcap
FLAGS= -Wall -D_GNU_SOURCE

TARGET=anonymizeIP 

OBJS = rijndael.o panonymizer.o anonymize_ip.o 

.SUFFIXES: .cpp

all: $(TARGET) 

$(TARGET): $(OBJS) 
	$(CC) $(FLAGS) $(OBJS) -o $@  $(LDFLAGS)

.cpp.o: 
	$(CC) -c $(CFLAGS) $< 

anonymize:
	$(CC) -g -Wall -D_GNU_SOURCE $(OBJS) anonymize_ip.cpp -o anonymizeIP $(LDFLAGS)

clean: 
	rm $(OBJS) $(TARGET) 
