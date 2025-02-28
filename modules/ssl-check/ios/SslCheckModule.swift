import ExpoModulesCore
import TrustKit

public class SslCheckModule: Module {
  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  public func definition() -> ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('SslCheck')` in JavaScript.
    Name("SslCheck")
    
    AsyncFunction("checkSSL") { (url: String, publicKey: String, promise: Promise) in
      do {
        let evaluator = try CustomTrustEvaluator(url: url, publicKey: publicKey)
        try evaluator.evaluate { success in
          if success {
            promise.resolve("success")
          } else {
            promise.reject(Exception.init(name: "Validation", description: "publicKey is not valid"))
          }
        }
      } catch {
        promise.reject(error)
      }
    }
  }
}

class CustomTrustEvaluator: NSObject {
  private let trustKit: TrustKit
  private var trustCompletion: ((Bool) -> Void)?
  private let url: URL
  private lazy var session: URLSession = {
    // IMPORTANT: The session object keeps a strong reference to the delegate. See more details:
    // https://developer.apple.com/documentation/foundation/nsurlsession/1411597-sessionwithconfiguration#parameters
    // Memory leak is prevented in didCompleteWithError method
    URLSession(configuration: .default, delegate: self, delegateQueue: nil)
  }()
  private var hadChallenge = false
  
  init(url urlString: String, publicKey: String) throws {
    guard let urlComponents = URLComponents(string: urlString),
          let url = urlComponents.url,
          let urlHost = urlComponents.host else {
      
      throw Exception.init(name: "ErrorUrl", description: "Can't extract host from url")
    }
    
    let trustKitConfig = [
      kTSKSwizzleNetworkDelegates: false,
      kTSKPinnedDomains: [
        urlHost: [
          // TrustKit requires at least 2 keys, so hardcoded second one, which is not valid
          kTSKPublicKeyHashes: [ publicKey, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" ]
        ]
      ]
    ] as [String : Any]
    
    trustKit = TrustKit(configuration: trustKitConfig)
    self.url = url
  }
  
  func evaluate(completion: @escaping (Bool) -> Void) throws {
    guard trustCompletion == nil else {
      throw Exception.init(name: "EvaluationError", description: "Can evaluate only one time using a same evaluator")
    }
    trustCompletion = completion
    session.dataTask(with: .init(url: url)).resume()
  }
}

extension CustomTrustEvaluator: URLSessionTaskDelegate {
  func urlSession(_ session: URLSession,
                  task: URLSessionTask,
                  didReceive challenge: URLAuthenticationChallenge,
                  completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    
    hadChallenge = true
    
    let completion: (URLSession.AuthChallengeDisposition, URLCredential?) -> Void = { [weak self] disposition, credential in
      completionHandler(disposition, credential)
      self?.trustCompletion?(disposition == .useCredential)
      self?.trustCompletion = nil
    }
    
    let handled = trustKit.pinningValidator.handle(challenge, completionHandler: completion)
    if !handled {
      completion(.cancelAuthenticationChallenge, nil)
    }
  }
  
  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
    if let trustCompletion {
      trustCompletion(!hadChallenge)
      self.trustCompletion = nil
    }
    // To prevent memory leak
    session.finishTasksAndInvalidate()
  }
}
