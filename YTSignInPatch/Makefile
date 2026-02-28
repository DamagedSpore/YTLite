ifeq ($(THEOS),)
$(error THEOS is not set)
endif

TARGET := iphone:clang:16.5:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = YTSignInPatch
YTSignInPatch_FILES = Tweak.xm
YTSignInPatch_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
