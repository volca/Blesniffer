//
//  CC2540Record.m
//  Blesniffer
//
//  Created by Hiroki Ishiura on 2016/11/11.
//  Copyright © 2016年 Hiroki Ishiura. All rights reserved.
//

#import "CC2540Record.h"

// MARK: -

@interface CC2540Record ()

- (instancetype)initWithBytes:(void *)bytes length:(NSInteger)length;

@end

@implementation CC2540Record

+ (instancetype)cc2540recordWithBytes:(void *)bytes length:(NSInteger)length {
	CC2540Record *record = [[CC2540CapturedRecord alloc] initWithBytes:bytes length:length];
	if (!record) {
		record = [[CC2540UnknownRecord alloc] initWithBytes:bytes length:length];
	}
	return record;
}

- (instancetype)initWithBytes:(void *)bytes length:(NSInteger)length {
	self = [super init];
	if (!self) {
		return nil;
	}
	
	return self;
}

@end

// MARK: -

struct CC2540CapturedRecordHeader {
	uint8  type;		// 0x00 is capture data.
	uint16 length;		// Hmmm... I don't use this field because its value may be corrupted.
	uint32 timestamp;
	uint8 preamble[1];	// BLE preamble?
	uint8 packet[0];	// BLE address?
} __attribute__((packed));

struct CC2540CapturedRecordFooter {
	uint8 rssi;			// it contains RSSI ?
	uint8 flags;			// it contains that this frame is valid or invalid ?
} __attribute__((packed));

const size_t HeaderLength = sizeof(struct CC2540CapturedRecordHeader);
const size_t FooterLength = sizeof(struct CC2540CapturedRecordFooter);
const size_t MinimumLength = HeaderLength + FooterLength;


@implementation CC2540CapturedRecord

- (instancetype)initWithBytes:(void *)bytes length:(NSInteger)length {
	if (![CC2540CapturedRecord validateBytes:bytes length:length]) {
		return nil;
	}
	
	self = [super initWithBytes:bytes length:length];
	if (!self) {
		return nil;
	}

	[self parseBytes:bytes length:length];
	
	return self;
}

- (void)dealloc {
	if (self.packetBytes) {
		free(self.packetBytes);
		self.packetBytes = nil;
	}
}

+ (BOOL)validateBytes:(uint8 *)bytes length:(NSInteger)length {
	if (length < MinimumLength) {
		return NO;
	}
	if (*bytes != 0x00) {
		return NO;
	}
	
	return YES;
}

static inline char itoh(int i) {
    if (i > 9) return 'A' + (i - 10);
    return '0' + i;
}

- (void)parseBytes:(uint8 *)bytes length:(NSInteger)length {
	struct CC2540CapturedRecordHeader *header = (struct CC2540CapturedRecordHeader *)bytes;
	
	// Hmm... Is this correct?
	const time_t nanoSeconds = 1000000000;
	const time_t microSeconds = 1000000;
	const time_t nanoToMicro = nanoSeconds / microSeconds;
	struct timeval packetTimestamp;
	packetTimestamp.tv_sec = (time_t)header->timestamp / nanoSeconds;
	packetTimestamp.tv_usec = (header->timestamp % nanoSeconds) / nanoToMicro;
	
	uint32 packetLength = (uint32)((size_t)length - MinimumLength);
	uint8_t *packetBytes = malloc(packetLength);
	memcpy(packetBytes, header->packet, packetLength);
    
    uint32 i;
    unsigned char *b;
    unsigned char *packetChars = malloc(packetLength * 2) + 1;
    b = header->packet;
    for (i = 0; i < packetLength; i++) {
        packetChars[i * 2] = itoh((b[i] >> 4) & 0xF);
        packetChars[i*2+1] = itoh(b[i] & 0xF);
    }
    packetLength *= 2;
    packetChars[packetLength] = '\0';

	struct CC2540CapturedRecordFooter *footer = (struct CC2540CapturedRecordFooter *)(bytes + length - FooterLength);
	int packetRssi = (char)footer->rssi;
	int packetChannel = footer->flags & 0x7f;
	int packetStatus = (footer->flags & 0x80 ? 1 : 0);
	
	int packetPduType = 0;
	if (packetLength > 5) {
		packetPduType = ((uint8 *)header->packet)[5] >> 4;
	}
    
    uint8_t mac[6];
    memcpy(mac, packetBytes + 6, 6);
	
	self.packetTimestamp = packetTimestamp;
	self.packetLength = packetLength;
    self.packetBytes = packetBytes;
    self.packetChars = packetChars;
	self.packetRssi = packetRssi;
	self.packetChannel = packetChannel;
	self.packetStatus = packetStatus;
	self.packetPduType = packetPduType;
    self.mac = &mac[0];
}

@end

// MARK: -

@implementation CC2540UnknownRecord

// No implementations.

@end
