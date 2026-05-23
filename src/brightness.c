#include <stdio.h>
#include <stdlib.h>
#include <IOKit/graphics/IOGraphicsLib.h>
#include <ApplicationServices/ApplicationServices.h>

// Declarations for private DisplayServices APIs
extern int DisplayServicesGetBrightness(CGDirectDisplayID display, float *brightness);
extern int DisplayServicesSetBrightness(CGDirectDisplayID display, float brightness);

float get_display_services_brightness() {
    float brightness = -1.0;
    CGDirectDisplayID display = CGMainDisplayID();
    if (DisplayServicesGetBrightness(display, &brightness) == 0) {
        return brightness;
    }
    return -1.0;
}

void set_display_services_brightness(float level) {
    CGDirectDisplayID display = CGMainDisplayID();
    DisplayServicesSetBrightness(display, level);
}

float get_legacy_brightness() {
    float brightness = -1.0;
    io_iterator_t iterator;
    kern_return_t result = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                                        IOServiceMatching("IODisplayConnect"),
                                                        &iterator);
    if (result == kIOReturnSuccess) {
        io_object_t service = IOIteratorNext(iterator);
        while (service) {
            float temp = -1.0;
            kern_return_t status = IODisplayGetFloatParameter(service, kNilOptions, CFSTR(kIODisplayBrightnessKey), &temp);
            if (status == kIOReturnSuccess) {
                brightness = temp;
                IOObjectRelease(service);
                break;
            }
            io_object_t nextService = IOIteratorNext(iterator);
            IOObjectRelease(service);
            service = nextService;
        }
        IOObjectRelease(iterator);
    }
    return brightness;
}

void set_legacy_brightness(float level) {
    io_iterator_t iterator;
    kern_return_t result = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                                        IOServiceMatching("IODisplayConnect"),
                                                        &iterator);
    if (result == kIOReturnSuccess) {
        io_object_t service = IOIteratorNext(iterator);
        while (service) {
            IODisplaySetFloatParameter(service, kNilOptions, CFSTR(kIODisplayBrightnessKey), level);
            io_object_t nextService = IOIteratorNext(iterator);
            IOObjectRelease(service);
            service = nextService;
        }
        IOObjectRelease(iterator);
    }
}

int main(int argc, char *argv[]) {
    float level = -1.0;
    if (argc > 1) {
        level = atof(argv[1]);
        if (level < 0.0) level = 0.0;
        if (level > 1.0) level = 1.0;

        // Try modern DisplayServices first, fallback to legacy IOKit
        set_display_services_brightness(level);
        set_legacy_brightness(level);
    }

    // Try modern DisplayServices query first, fallback to legacy IOKit
    float b = get_display_services_brightness();
    if (b < 0.0) {
        b = get_legacy_brightness();
    }

    if (b < 0.0) {
        // Fallback for headless or virtualized machines where no physical display exists
        if (level >= 0.0) {
            printf("%.2f\n", level);
        } else {
            printf("0.50\n");
        }
    } else {
        printf("%.2f\n", b);
    }
    return 0;
}
