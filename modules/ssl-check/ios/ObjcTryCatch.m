//
//  ObjcTryCatch.m
//  SslCheck
//
//  Created by Oleksandr Koryttsev on 03.03.2025.
//

#import <Foundation/Foundation.h>
#import "ObjcTryCatch.h"

NSException * _Nullable ObjcTryCatch(void (^ _Nonnull block)(void)) {
  @try {
    block();
    return nil;
  } @catch (NSException *exception) {
    return exception;
  }
}
