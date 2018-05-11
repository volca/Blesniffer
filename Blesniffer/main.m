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
        output[i] = strtol(buf, NULL, 16);
    }
    
    return 0;
}

int main(int argc, const char *argv[]) {
	@autoreleasepool {
		const char *argv0 = argv[0];

		int channelNumber = 0;
		int deviceNumber = 0;
        uint8_t macFilter[6];
        
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
        
        while (ReadingRecord) {
			@autoreleasepool {
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
					CC2540CapturedRecord *capturedRecord = (CC2540CapturedRecord *)record;
                    /*
					verbose("%c", (capturedRecord.packetPduType > 0) ?
						((char)(capturedRecord.packetPduType) + '0') : '?');
                     */
					//[file write:capturedRecord];
                    fprintf(stdout, capturedRecord.packetChars);
                    fprintf(stdout, "\n");
				}
                
                [cc2540 start:channelNumber];

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
