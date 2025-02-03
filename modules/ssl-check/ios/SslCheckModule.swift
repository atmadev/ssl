import ExpoModulesCore
import Alamofire

public class SslCheckModule: Module {
  private var session: Session?

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  public func definition() -> ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('SslCheck')` in JavaScript.
    Name("SslCheck")

    // Defines a JavaScript function that always returns a Promise and whose native code
    // is by default dispatched on the different thread than the JavaScript runtime runs on.
      AsyncFunction("checkSSL") { (url: String, publicKey: String, promise: Promise) in
//          validateCertificate(url: url, domain: "wegloat.gloat-staging.gloat.com", publicKeyHash: publicKey) { isValid, error in
//              if isValid {
//                  print("Certificate is valid")
//                  promise.resolve("++")
//              } else {
//                  print("Certificate validation failed: \(error?.localizedDescription ?? "")")
//                  promise.reject(error!)
//              }
//          }
//          return

                // Convert the public key from Base64 string to Data
                guard let publicKeyData = Data(base64Encoded: publicKey) else {
                    promise.reject(
                        Exception.init(name: "ErrorPublicKey", description: "Error base64 converting public key")
                    )
                  return
                }

                // Create a custom ServerTrustManager
                let serverTrustManager = ServerTrustManager(allHostsMustBeEvaluated: true, evaluators: [
                  "wegloat.gloat-staging.gloat.com": PublicKeyPinningEvaluator(publicKeyData: publicKeyData)
                ])

          let monitor = LoggingEventMonitor()

                // Create a session with the ServerTrustManager
          self.session = Session(serverTrustManager: serverTrustManager, eventMonitors: [monitor])

                // Make the network request
          self.session!.request(url).validate().response { response in
                  switch response.result {
                  case .success:
                      promise.resolve("success")
                  case .failure(let error):
                      promise.reject(error)
                  }
                }
    }
  }
}

// ========= OPTION 1 Chat-GPT =============
final class PublicKeyPinningEvaluator: ServerTrustEvaluating {
  let publicKeyData: Data

  init(publicKeyData: Data) {
    self.publicKeyData = publicKeyData
  }

  func evaluate(_ trust: SecTrust, forHost host: String) throws {
    // Extract the server's public key from the certificate chain
    guard let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) else {
      throw AFError.serverTrustEvaluationFailed(reason: .noCertificatesFound)
    }

    guard let serverPublicKey = SecCertificateCopyKey(serverCertificate),
          let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) as Data? else {
      throw AFError.serverTrustEvaluationFailed(reason: .noPublicKeysFound)
    }

      print("Check publicKey: \(publicKeyData)")
      print("Certificate publicKey: \(serverPublicKeyData)")

    // Compare the server's public key with the provided public key
    if serverPublicKeyData != publicKeyData {
        throw AFError.serverTrustEvaluationFailed(reason: .revocationPolicyCreationFailed)
    }
  }
}

final class LoggingEventMonitor: EventMonitor {
    let queue = DispatchQueue(label: "com.example.LoggingEventMonitor")

    func requestDidFinish(_ request: Request) {
        print("Request finished: \(request)")
    }

    func request(_ request: DataRequest, didValidateRequest urlRequest: URLRequest?, response: HTTPURLResponse, withResult result: Result<Void, Error>) {
        switch result {
        case .success:
            print("Validation succeeded for request to: \(urlRequest?.url?.absoluteString ?? "Unknown URL")")
        case .failure(let error):
            print("Validation failed for request to: \(urlRequest?.url?.absoluteString ?? "Unknown URL") with error: \(error.localizedDescription)")
        }
    }
}

// =============== OPTION 2 Claude ==============

import Foundation
import CommonCrypto

var session: Session?

func validateCertificate(url: String, domain: String, publicKeyHash: String, completion: @escaping (Bool, Error?) -> Void) {
    let evaluator = CustomServerTrustEvaluating(publicKeyHash: publicKeyHash)
    session = Session(serverTrustManager: ServerTrustManager(evaluators: [domain: evaluator]))
    print("domain: \(domain)")
    print("url: \(url)")

    session!.request(url).response { response in
        switch response.result {
        case .success:
            completion(true, nil)
        case .failure(let error):
            completion(false, error)
        }
    }
}

final class CustomServerTrustEvaluating: ServerTrustEvaluating {
    private let publicKeyHash: String

    init(publicKeyHash: String) {
        self.publicKeyHash = publicKeyHash
    }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        print("Evaluating certificate for host: \(host)")

        // Get the certificate chain
        let certificateCount = SecTrustGetCertificateCount(trust)
        guard certificateCount > 0,
              let certificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            throw AFError.serverTrustEvaluationFailed(reason: .noPublicKeysFound)
        }

        print("> 1")

        // Get public key data
        guard let publicKey = SecCertificateCopyKey(certificate),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data else {
            throw AFError.serverTrustEvaluationFailed(reason: .noPublicKeysFound)
        }

        print("> 2")

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        publicKeyData.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
        }

        let computedHash = Data(hash).base64EncodedString()

        print("Check publicKey: \(publicKeyHash)")
        print("Certificate publicKey: \(computedHash)")

        guard computedHash == publicKeyHash else {
            throw AFError.serverTrustEvaluationFailed(reason: .customEvaluationFailed(error: Exception.init(name: "CertEvaluationError", description: "Error matching certificate")))
        }
    }
}
