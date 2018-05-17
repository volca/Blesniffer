//
//  main.m
//  Blesniffer
//
//  Created by Hiroki Ishiura on 2016/11/03.
//  Copyright © 2016年 Hiroki Ishiura. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <unistd.h>
#import "UsbDeviceManager.h"
#import "UsbDevice.h"
#import "CC2540.h"
#import "CC2540Record.h"
#import "PcapDumpFile.h"

#define NONE                 "\e[0m"
#define BLACK                "\e[0;30m"
#define L_BLACK              "\e[1;30m"
#define RED                  "\e[0;31m"
#define L_RED                "\e[1;31m"
#define GREEN                "\e[0;32m"
#define L_GREEN              "\e[1;32m"
#define BROWN                "\e[0;33m"
#define YELLOW               "\e[1;33m"
#define BLUE                 "\e[0;34m"
#define L_BLUE               "\e[1;34m"
#define PURPLE               "\e[0;35m"
#define L_PURPLE             "\e[1;35m"
#define CYAN                 "\e[0;36m"
#define L_CYAN               "\e[1;36m"
#define GRAY                 "\e[0;37m"
#define WHITE                "\e[1;37m"

#define BOLD                 "\e[1m"
#define UNDERLINE            "\e[4m"
#define BLINK                "\e[5m"
#define REVERSE              "\e[7m"
#define HIDE                 "\e[8m"
#define CLEAR                "\e[2J"
#define CLRLINE              "\r\e[K"

#define PACKET_MAX_LEN       120

static volatile const char *ApplicationVersion __attribute__((unused)) = "1.0.1";

static volatile BOOL VerboseMode = NO;
static volatile BOOL ReadingRecord = YES;

static void verbose(const char *format, ...) {
	if (!VerboseMode) {
		return;
	}
	
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fflush(stderr);
}

static void signalHandler(int signal) {
	ReadingRecord = NO;
}

static int parseMac(char *str, uint8_t *output) {
    int i;
    size_t len = strlen(str);
    char buf[3] = {'\0','\0','\0'};

    if (12 != len) {
        return -1;
    }
    
    for (i = 0; i < len / 2; i++) {
        buf[0] = str[i * 2];
        buf[1] = str[i * 2 + 1];
        output[6 - 1 - i] = strtol(buf, NULL, 16);
    }
    
    return 0;
}

static void hexPrint(uint8_t *data, int len) {
    uint32 i;
    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02X ", data[i]);
    }
}

int main(int argc, const char *argv[]) {
	@autoreleasepool {
		const char *argv0 = argv[0];

		int channelNumber = 0;
		int deviceNumber = 0;
        uint8_t macFilter[6];
        memset(macFilter, 0, sizeof(macFilter));
        uint8_t hasFilter = 0;
        
		{
			int optch, ret;
			extern char *optarg;
			extern int optind;
			extern int opterr;
            while ((optch = getopt(argc, (char **)argv, "c:d:m:v")) != -1) {
				switch (optch) {
					case 'c':
						channelNumber = atoi(optarg);
						if (channelNumber < 0 || channelNumber > 39) {
							fprintf(stderr, "%s: Channel number is out of range.\n", argv0);
							exit(1);
						}
						break;
					case 'd':
						deviceNumber = atoi(optarg);
						break;
					case 'v':
						VerboseMode = YES;
						break;
                    case 'm':
                        ret = parseMac(optarg, macFilter);
                        if (-1 == ret) {
                            fprintf(stderr, "%s: Wrong mac address.\n", optarg);
                            exit(1);
                        }
                        
                        fprintf(
                            stdout,
                            "Mac Filter: %02X %02X %02X %02X %02X %02X.\n",
                            macFilter[0],
                            macFilter[1],
                            macFilter[2],
                            macFilter[3],
                            macFilter[4],
                            macFilter[5]
                        );
                        hasFilter = 1;
                        break;
					default:
						exit(1);
						break;
				}
			}
			argc -= optind;
			argv += optind;
		}

		if (argc < 1) {
			NSString *applicationPath = [NSString stringWithCString:argv0 encoding:NSUTF8StringEncoding];
			NSString *applicationFile = [applicationPath lastPathComponent];
			const char *applicationName = [applicationFile UTF8String];
			
			fprintf(stderr, "Usage: %s [-c channel#] [-d device#] [-v] output.pcap\n", applicationName);
			fprintf(stderr, "  (!) control-c makes exiting packet capturing.\n");
			exit(1);
		}
		NSString *output = [NSString stringWithCString:argv[0] encoding:NSUTF8StringEncoding];
		if ([output isEqualToString:@"-"]) {
			verbose("output is stdout.\n");
		} else {
			if (![[output lowercaseString] hasSuffix:@".pcap"]) {
				output = [NSString stringWithFormat:@"%@.pcap", output];
			}
		}
		const char *outputFile = [output UTF8String];

		
		UsbDeviceManager *manager = [UsbDeviceManager new];
		if (![manager open]) {
			fprintf(stderr, "%s: Could not open USB device manager.\n", argv0);
			exit(1);
		}
		
		NSInteger vendorId = [CC2540 vendorId];
		NSInteger productId = [CC2540 productId];
		NSArray<UsbDevice *> *deviceList = [manager deviceListWithVendorId:vendorId productId:productId];
		if (deviceList.count < 1) {
			fprintf(stderr, "%s: No CC2540 USB dongles.\n", argv0);
			exit(1);
		}
		
		if (deviceNumber < 0 || deviceNumber >= deviceList.count) {
			fprintf(stderr, "%s: Device number is out of range.\n", argv0);
			exit(1);
		}
	
		UsbDevice *device = deviceList[deviceNumber];
		verbose("device: %s\n", [device.path UTF8String]);
		CC2540 *cc2540 = [[CC2540 alloc] initWithUsbDevice:device];
		if (![cc2540 open]) {
			fprintf(stderr, "%s: Could not open CC2540 USB dongle.\n", argv0);
			exit(1);
		}
		
		NSString *filename = [NSString stringWithCString:outputFile encoding:NSUTF8StringEncoding];
		PcapDumpFile *file = [[PcapDumpFile alloc] init];
		if (![file open:filename]) {
			fprintf(stderr, "%s: Could not open output.\n", argv0);
			exit(1);
		}
		if (![cc2540 start: channelNumber]) {
			fprintf(stderr, "%s: Could not start capturing packet.\n", argv0);
			exit(1);
		}

		verbose("start to capture.\n");
		signal(SIGINT, signalHandler);
		NSUInteger number = 0;
        NSTimeInterval currentTime, diff, prevTime = [[NSDate date] timeIntervalSince1970];

        while (ReadingRecord) {
			@autoreleasepool {
                currentTime = [[NSDate date] timeIntervalSince1970];
                diff = currentTime - prevTime;
                if (diff > 1.5) {
                    [cc2540 stop];
                    [cc2540 start:channelNumber];
                }
                
                prevTime = currentTime;
				CC2540Record *record = [cc2540 read];
				if (!record) {
					if (ReadingRecord) {
						fprintf(stderr, "%s: Could not read data.\n", argv0);
					} else {
						verbose("\n");
					}
					break;
				}
				if ([record isKindOfClass:[CC2540CapturedRecord class]]) {
					CC2540CapturedRecord *data = (CC2540CapturedRecord *)record;
					//verbose("%c", (capturedRecord.packetPduType > 0) ?
					//	((char)(capturedRecord.packetPduType) + '0') : '?');
					//[file write:capturedRecord];
                    
                    if (hasFilter) {
                        if (memcmp(macFilter, data.mac, 6) != 0) {
                            continue;
                        }
                         
                    }
                    
                    if (data.packetLength > PACKET_MAX_LEN) {
                        continue;
                    }
                    
                    fprintf(
                        stdout,
                        GRAY "%d " BLUE "%d " YELLOW "%02X%02X%02X%02X%02X%02X " NONE,
                            
                        data.packetChannel,
                        data.packetPduType,
                        data.mac[5],data.mac[4],data.mac[3],data.mac[2],data.mac[1],data.mac[0]
                    );
                    hexPrint(data.packetBytes + 12, data.packetLength - 12 - 3);
                    fprintf(stdout, L_RED "%d\n" NONE, data.packetRssi);
				}

			}
			number++;
		}
		verbose("stop capturing.\n");

		[cc2540 stop];
		[file close];
		[cc2540 close];
		[manager close];
		
	}
	
    exit(0);
}
