import { requireNativeModule } from "expo-modules-core"

// It loads the native module object from the JSI or falls back to
// the bridge module (from NativeModulesProxy) if the remote debugger is on.
let SslCheckModule: any

export async function checkSSL(
  url: string,
  publicKey: string,
  publicKey2: string
) {
  // Lazy init
  if (SslCheckModule === undefined)
    SslCheckModule = requireNativeModule("SslCheck")

  return await SslCheckModule.checkSSL(url, publicKey, publicKey2)
}
