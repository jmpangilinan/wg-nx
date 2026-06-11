ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment")
endif

include $(DEVKITPRO)/libnx/switch_rules

TARGET		:=	libwireguard
BUILD		:=	build
SOURCES		:=	src library/crypto
INCLUDES	:=	include library/crypto src

# ─── lwIP ─────────────────────────────────────────────────────
LWIP_DIR       := $(CURDIR)/library/lwip
LWIP_INC       := $(LWIP_DIR)/src/include
LWIP_ARCH_INC  := $(CURDIR)/lwip-relay/include
LWIP_ARCH_SRC  := $(CURDIR)/lwip-relay/src

# lwIP core sources (NO_SYS, IPv4-only)
LWIP_CORE_C := init def inet_chksum ip mem memp netif pbuf raw stats sys timeouts tcp tcp_in tcp_out udp dns
LWIP_IPV4_C := icmp ip4 ip4_addr ip4_frag

LWIP_CFILES := $(addsuffix .c, $(addprefix $(LWIP_DIR)/src/core/, $(LWIP_CORE_C))) \
               $(addsuffix .c, $(addprefix $(LWIP_DIR)/src/core/ipv4/, $(LWIP_IPV4_C)))

LWIP_RELAY_C := $(LWIP_ARCH_SRC)/sys_arch.c $(LWIP_ARCH_SRC)/wg_netif.c

INCLUDES += $(LWIP_INC) $(LWIP_ARCH_INC) $(LWIP_ARCH_INC)/arch

ARCH		:=	-march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC

CFLAGS		:=	-g -Wall -O2 -ffunction-sections $(ARCH)
CXXFLAGS	:=	$(CFLAGS) -fno-rtti -fno-exceptions

LIBDIRS		:=	$(PORTLIBS) $(LIBNX)

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(CURDIR)/$(dir)/*.c)))
OFILES		:=	$(CFILES:.c=.o)

# lwIP object files (name them with lwip_ prefix to avoid collisions)
LWIP_OFILES := $(addprefix lwip_, $(notdir $(LWIP_CFILES:.c=.o))) \
               $(notdir $(LWIP_RELAY_C:.c=.o))

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			-I$(LWIP_INC) -I$(LWIP_ARCH_INC) -I$(LWIP_ARCH_INC)/arch

.PHONY: all clean

all: $(BUILD) $(OUTPUT).a

$(BUILD):
	@mkdir -p $@

$(OUTPUT).a: $(OFILES:%=$(BUILD)/%) $(LWIP_OFILES:%=$(BUILD)/%)
	@echo linking $(notdir $@)
	@rm -f $@
	@$(AR) -rc $@ $^

$(BUILD)/%.o: %.c | $(BUILD)
	@echo $(notdir $<)
	@$(CC) -MMD -MP -MF $(DEPSDIR)/$*.d $(CFLAGS) $(INCLUDE) -c $< -o $@

# lwIP core objects — compiled from explicit paths
$(BUILD)/lwip_%.o: $(LWIP_DIR)/src/core/%.c | $(BUILD)
	@echo lwip:$(notdir $<)
	@$(CC) -MMD -MP -MF $(DEPSDIR)/lwip_$*.d $(CFLAGS) $(INCLUDE) -c $< -o $@

# lwIP ipv4 objects
$(BUILD)/lwip_%.o: $(LWIP_DIR)/src/core/ipv4/%.c | $(BUILD)
	@echo lwip:$(notdir $<)
	@$(CC) -MMD -MP -MF $(DEPSDIR)/lwip_$*.d $(CFLAGS) $(INCLUDE) -c $< -o $@

# lwip-relay objects
$(BUILD)/%.o: $(LWIP_ARCH_SRC)/%.c | $(BUILD)
	@echo $(notdir $<)
	@$(CC) -MMD -MP -MF $(DEPSDIR)/$*.d $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	@rm -rf $(BUILD) $(TARGET).a

-include $(wildcard $(BUILD)/*.d)
