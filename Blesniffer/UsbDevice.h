//
//  UsbDevice.h
//  Blesniffer
//
//  Created by Hiroki Ishiura on 2016/11/03.
//  Copyright © 2016年 Hiroki Ishiura. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <IOKit/usb/IOUSBLib.h>

@class UsbDeviceInterface;


@interface UsbDevice : NSObject

@property (strong) NSString *name;
@property (strong) NSString *path;

- (BOOL)open;
- (BOOL)close;
- (BOOL)deviceRequest:(IOUSBDevRequest *)request;
- (NSInteger)getConfiguration;
- (BOOL)setConfiguration:(NSInteger)value;
- (NSArray<UsbDeviceInterface *> *)interfaceList;

@end
