import Foundation
import Clibsodium

public struct Sha256Hash {
    //public let BytesMin = Int(crypto_hash_sha256_bytes_min())
    //public let BytesMax = Int(crypto_hash_sha256_bytes_max())
    public let Bytes = Int(crypto_hash_sha256_bytes())
    //public let KeyBytesMax = Int(crypto_auth_hmacsha256_KEYBYTES)

    //public let Primitive = String(validatingUTF8: crypto_hash_sha256_primitive())
    
    
    //let x = crypto_hash_sha256_BYTES
}

//extension Sha256Hash {
//    public class Stream {
//        private var state: UnsafeMutableRawBufferPointer
//        private var opaqueState: OpaquePointer
//        public var outputLength: Int = 0
//
//        init?(key: Bytes?, outputLength: Int) {
//            state = UnsafeMutableRawBufferPointer.allocate(byteCount: crypto_hash_sha256_statebytes(), alignment: 64)
//            guard state.baseAddress != nil else { return nil }
//            opaqueState = OpaquePointer(state.baseAddress!)
//            guard .SUCCESS == crypto_hash_sha256_init(
//                opaqueState,
//                key, key?.count ?? 0,
//                outputLength
//            ).exitCode else { return nil }
//
//            self.outputLength = outputLength
//        }
//
//        deinit {
//            state.deallocate()
//        }
//    }
//}

extension Sha256Hash {
    /**
     Computes a fixed-length fingerprint for an arbitrary long message. A key can also be specified. A message will always have the same fingerprint for a given key, but different keys used to hash the same message are very likely to produce distinct fingerprints.

     - Parameter message: The message from which to compute the fingerprint.
     - Parameter key: Optional key to use while computing the fingerprint.

     - Returns: The computed fingerprint.
     */
//    public func hash(message: Bytes, key: Bytes? = nil) -> Bytes? {
//        return hash(message: message, key: key, outputLength: Bytes)
//    }

    /**
     Computes a fixed-length fingerprint for an arbitrary long message. A message will always have the same fingerprint for a given key, but different keys used to hash the same message are very likely to produce distinct fingerprints.

     - Parameter message: The message from which to compute the fingerprint.
     - Parameter key: The key to use while computing the fingerprint.
     - Parameter outputLength: Desired length of the computed fingerprint.

     - Returns: The computed fingerprint.
     */
    public func hmac(message: Bytes, key: Bytes) -> Bytes? {
        var output = Array<UInt8>(count: Bytes)

        guard .SUCCESS == crypto_auth_hmacsha256(
            &output,
            message,
            UInt64(message.count),
            key
        ).exitCode else { return nil }

        return output
    }

    /**
     Computes a fixed-length fingerprint for an arbitrary long message.

     - Parameter message: The message from which to compute the fingerprint.
     - Parameter outputLength: Desired length of the computed fingerprint.

     - Returns: The computed fingerprint.
     */
    public func hash(message: Bytes) -> Bytes? {
        var output = Array<UInt8>(count: Bytes)
        
        guard .SUCCESS == crypto_hash_sha256(
            &output,
            message,
            UInt64(message.count)
            ).exitCode else { return nil }
        
        return output
    }
}

//extension Sha256Hash {
//    /**
//     Initializes a `Stream` object to compute a fixed-length fingerprint for an incoming stream of data.arbitrary long message. Particular data will always have the same fingerprint for a given key, but different keys used to hash the same data are very likely to produce distinct fingerprints.
//
//     - Parameter key: Optional key to use while computing the fingerprint.
//
//     - Returns: The initialized `Stream`.
//     */
//    public func initStream(key: Bytes? = nil) -> Stream? {
//        return Stream(key: key, outputLength: Bytes)
//    }
//
//    /**
//     Initializes a `Stream` object to compute a fixed-length fingerprint for an incoming stream of data.arbitrary long message. Particular data will always have the same fingerprint for a given key, but different keys used to hash the same data are very likely to produce distinct fingerprints.
//
//     - Parameter key: Optional key to use while computing the fingerprint.
//     - Parameter outputLength: Desired length of the computed fingerprint.
//
//     - Returns: The initialized `Stream`.
//     */
//    public func initStream(key: Bytes?, outputLength: Int) -> Stream? {
//        return Stream(key: key, outputLength: outputLength)
//    }
//
//    /**
//     Initializes a `Stream` object to compute a fixed-length fingerprint for an incoming stream of data.arbitrary long message.
//
//     - Parameter: outputLength: Desired length of the computed fingerprint.
//
//     - Returns: The initialized `Stream`.
//     */
//    public func initStream(outputLength: Int) -> Stream? {
//        return Stream(key: nil, outputLength: outputLength)
//    }
//}
//
//extension Sha256Hash.Stream {
//    /**
//     Updates the hash stream with incoming data to contribute to the computed fingerprint.
//
//     - Parameter input: The incoming stream data.
//
//     - Returns: `true` if the data was consumed successfully.
//     */
//    @discardableResult
//    public func update(input: Bytes) -> Bool {
//        return .SUCCESS == crypto_hash_sha256_update(
//            opaqueState,
//            input, UInt64(input.count)
//        ).exitCode
//    }
//
//    /**
//     Signals that the incoming stream of data is complete and triggers computation of the resulting fingerprint.
//
//     - Returns: The computed fingerprint.
//     */
//    public func final() -> Bytes? {
//        let outputLen = outputLength
//        var output = Array<UInt8>(count: outputLen)
//        guard .SUCCESS == crypto_hash_sha256_final(
//            opaqueState,
//            &output, outputLen
//        ).exitCode else { return nil }
//
//        return output
//    }
//}

extension Sha256Hash: SecretKeyGenerator {
    public var KeyBytes: Int { return Int(crypto_auth_hmacsha256_KEYBYTES) }
    public typealias Key = Bytes
    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_auth_hmacsha256_keygen

}
