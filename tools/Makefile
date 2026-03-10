#hack
TOOL_DIRS := $(patsubst %/Makefile,%,$(wildcard */Makefile))
.PHONY: $(TOOL_DIRS) all

all: $(TOOL_DIRS)

$(TOOL_DIRS):
	$(MAKE) -C $@

.PHONY: clean

clean:
	for d in */ ; do \
		$(MAKE) -C $$d clean; \
	done
