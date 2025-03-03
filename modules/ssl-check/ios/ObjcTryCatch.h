//
//  ObjcTryCatch.h
//  Pods
//
//  Created by Oleksandr Koryttsev on 03.03.2025.
//

#ifndef ObjcTryCatch_h
#define ObjcTryCatch_h
// Be aware of potentional memory leaks using this catcher
// https://medium.com/@quentinfasquel/leaks-caused-by-catching-nsexception-in-swift-1f6cbb95c02c
NSException * _Nullable ObjcTryCatch(void (^ _Nonnull block)(void));

#endif /* ObjcTryCatch_h */
