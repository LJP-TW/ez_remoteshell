# CONFIG_DEBUG = y

SERVER_TARGET = ez_rsserver
CLIENT_TARGET = ez_rsclient

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SERVER_SOURCES := $(wildcard $(SRCDIR)/server/*.c)
SERVER_OBJECTS := $(SERVER_SOURCES:$(SRCDIR)/server/%.c=$(OBJDIR)/server/%.o)

CLIENT_SOURCES := $(wildcard $(SRCDIR)/client/*.c)
CLIENT_OBJECTS := $(CLIENT_SOURCES:$(SRCDIR)/client/%.c=$(OBJDIR)/client/%.o)

SHARED_SOURCES := $(wildcard $(SRCDIR)/shared/*.c)
SHARED_OBJECTS := $(SHARED_SOURCES:$(SRCDIR)/shared/%.c=$(OBJDIR)/shared/%.o)

CC = gcc
CFLAGS = -std=gnu11 -Wall -I $(SRCDIR)

LD = gcc
LDFLAGS = -lssl -lcrypto

RM = rm -f

ifeq ($(CONFIG_DEBUG),y)
CFLAGS += -DDEBUG
endif

all: server client

server: $(BINDIR)/$(SERVER_TARGET)

client: $(BINDIR)/$(CLIENT_TARGET)

$(BINDIR)/$(SERVER_TARGET): $(SHARED_OBJECTS) $(SERVER_OBJECTS)
	@mkdir -p $(BINDIR)
	@echo $(LD) $(SHARED_OBJECTS) $(SERVER_OBJECTS) $(LDFLAGS) -o $@
	@$(LD) $(SHARED_OBJECTS) $(SERVER_OBJECTS) $(LDFLAGS) -o $@

$(BINDIR)/$(CLIENT_TARGET): $(SHARED_OBJECTS) $(CLIENT_OBJECTS)
	@mkdir -p $(BINDIR)
	@echo $(LD) $(SHARED_OBJECTS) $(CLIENT_OBJECTS) $(LDFLAGS) -o $@
	@$(LD) $(SHARED_OBJECTS) $(CLIENT_OBJECTS) $(LDFLAGS) -o $@

$(SHARED_OBJECTS): $(OBJDIR)/shared/%.o: $(SRCDIR)/shared/%.c
	@mkdir -p $(OBJDIR)/shared
	@echo $(CC) $(CFLAGS) -c $< -o $@
	@$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_OBJECTS): $(OBJDIR)/server/%.o: $(SRCDIR)/server/%.c
	@mkdir -p $(OBJDIR)/server
	@echo $(CC) $(CFLAGS) -c $< -o $@
	@$(CC) $(CFLAGS) -c $< -o $@

$(CLIENT_OBJECTS): $(OBJDIR)/client/%.o: $(SRCDIR)/client/%.c
	@mkdir -p $(OBJDIR)/client
	@echo $(CC) $(CFLAGS) -c $< -o $@
	@$(CC) $(CFLAGS) -c $< -o $@

.PHONY: runserver
runserver:
	@echo $(SERVER_TARGET)": default PEM password is 'abcd1234', create a new one for yourself!"
	@echo $(SERVER_TARGET)": check keys/Makefile"
	./$(BINDIR)/$(SERVER_TARGET) -i 0.0.0.0 -p 5566 -f config/server_config

.PHONY: runclient
runclient:
	@echo $(CLIENT_TARGET)": default PEM password is 'abcd1234', create a new one for yourself!"
	@echo $(CLIENT_TARGET)": check keys/Makefile"
	./$(BINDIR)/$(CLIENT_TARGET) -i 127.0.0.1 -p 5566 -f config/client_config

.PHONY: runfakeclient
runfakeclient:
	@echo $(CLIENT_TARGET)": default PEM password is 'abcd1234', create a new one for yourself!"
	@echo $(CLIENT_TARGET)": check keys/Makefile"
	./$(BINDIR)/$(CLIENT_TARGET) -i 127.0.0.1 -p 5566 -f config/fakeclient_config

.PHONY: clean
clean:
	@$(RM) $(SERVER_OBJECTS)
	@$(RM) $(CLIENT_OBJECTS)
	@$(RM) $(SHARED_OBJECTS)

.PHONY: remove
remove: clean
	@$(RM) $(BINDIR)/$(SERVER_TARGET)
	@$(RM) $(BINDIR)/$(CLIENT_TARGET)
