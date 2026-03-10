HOST_CC ?= gcc
HOST_CFLAGS ?= -O2
HOST_LDFLAGS ?=

#dependency thing
HOST_CFLAGS += -MMD -MP

$(TOOL): $(OBJS)
	$(HOST_CC) $(OBJS) $(HOST_LDFLAGS) -o $@

%.o: %.c
	$(HOST_CC) $(HOST_CFLAGS) -c -o $@ $<

#dependency thing
-include $(OBJS:.o=.d)

.PHONY: clean
clean:
	-rm -f $(OBJS) $(OBJS:.o=.d) $(TOOL)
