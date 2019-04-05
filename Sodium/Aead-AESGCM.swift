//
//  Aead-AESGCM.swift
//  sqrl
//
//  Created by Jeff Arthur on 01/04/2019.
//  Copyright © 2019 Jeff Arthur. All rights reserved.
//

import Foundation
import Clibsodium

//public struct AeadAESGCM {
//    public let aes256gcm = AES256GCM()
//    let x = crypto_aead_aes256gcm_ABYTES
//}

extension Aead {
    public struct AES256GCM {
        public let ABytes = Int(crypto_aead_aes256gcm_abytes())
        public typealias MAC = Bytes
    }
}

extension Aead.AES256GCM {
    /**
     Encrypts a message with a shared secret key.
     
     - Parameter message: The message to encrypt.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: A typical use for these data is to authenticate version numbers, timestamps or monotonically increasing counters
     
     - Returns: A `Bytes` object containing the nonce and authenticated ciphertext.
     */
//    public func encrypt(message: Bytes, secretKey: Key, additionalData: Bytes? = nil) -> Bytes? {
//        guard let (authenticatedCipherText, nonce): (Bytes, Nonce) = encrypt(
//            message: message,
//            secretKey: secretKey,
//            additionalData: additionalData
//            ) else { return nil }
//        
//        return nonce + authenticatedCipherText
//    }
    
    /**
     Encrypts a message with a shared secret key.
     
     - Parameter message: The message to encrypt.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: A typical use for these data is to authenticate version numbers, timestamps or monotonically increasing counters
     
     - Returns: The authenticated ciphertext and encryption nonce.
     */
    public func encrypt(message: Bytes, secretKey: Aead.AES256GCM.Key, additionalData: Bytes? = nil) -> (cipherText: Bytes, nonce: Aead.AES256GCM.Nonce,authTag:Aead.AES256GCM.MAC )? {
        guard secretKey.count == KeyBytes else { return nil }
        
        var cipherText = Bytes(count: message.count)
        //var authenticatedCipherTextLen: UInt64 = 0
        var tag = Bytes(count: ABytes)
        var tagLen = UInt64(0)
        let nonce = self.nonce()
        
        guard .SUCCESS == crypto_aead_aes256gcm_encrypt_detached(&cipherText, &tag, &tagLen, message, UInt64(message.count), additionalData, UInt64(additionalData?.count ?? 0), nil, nonce, secretKey).exitCode else { return nil }
           

        
        
//        guard .SUCCESS == crypto_aead_aes256gcm_encrypt (
//            &authenticatedCipherText, &authenticatedCipherTextLen,
//            message, UInt64(message.count),
//            additionalData, UInt64(additionalData?.count ?? 0),
//            nil, nonce, secretKey
//            ).exitCode else { return nil }
        
        return (cipherText: cipherText, nonce: nonce, authTag:tag)
    }
}

extension Aead.AES256GCM {
    /**
     Decrypts a message with a shared secret key.
     
     - Parameter nonceAndAuthenticatedCipherText: A `Bytes` object containing the nonce and authenticated ciphertext.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: Must be used same `Bytes` that was used to encrypt, if `Bytes` deferred will return nil
     
     - Returns: The decrypted message.
     */
    public func decrypt(nonceAndAuthenticatedCipherText: Bytes, secretKey: Key, additionalData: Bytes? = nil) -> Bytes? {
        guard nonceAndAuthenticatedCipherText.count >= ABytes + NonceBytes else { return nil }
        
        let nonce = nonceAndAuthenticatedCipherText[..<NonceBytes].bytes as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText[NonceBytes...].bytes
        
        return decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: nonce, additionalData: additionalData)
    }
    
    /**
     Decrypts a message with a shared secret key.
     
     - Parameter authenticatedCipherText: A `Bytes` object containing authenticated ciphertext.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: Must be used same `Bytes` that was used to encrypt, if `Bytes` deferred will return nil
     
     - Returns: The decrypted message.
     */
    public func decrypt(authenticatedCipherText: Bytes, secretKey: Key, nonce: Nonce, additionalData: Bytes? = nil) -> Bytes? {
        guard authenticatedCipherText.count >= ABytes else { return nil }
        
        var message = Bytes(count: authenticatedCipherText.count - ABytes)
        var messageLen: UInt64 = 0
        
        guard .SUCCESS == crypto_aead_aes256gcm_decrypt (
            &message, &messageLen,
            nil,
            authenticatedCipherText, UInt64(authenticatedCipherText.count),
            additionalData, UInt64(additionalData?.count ?? 0),
            nonce, secretKey
            ).exitCode else { return nil }
        
        return message
    }
}

extension Aead.AES256GCM: NonceGenerator {
    public typealias Nonce = Bytes
    public var NonceBytes: Int { return Int(crypto_aead_aes256gcm_npubbytes()) }
}

extension Aead.AES256GCM: SecretKeyGenerator {
    public var KeyBytes: Int { return Int(crypto_aead_aes256gcm_keybytes()) }
    public typealias Key = Bytes
    
    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_aead_aes256gcm_keygen
}
