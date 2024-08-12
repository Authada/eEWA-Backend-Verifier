/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.domain.authchan

import COSE.Attribute
import COSE.HeaderKeys
import cbor.Cbor
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.verifier.endpoint.domain.authchan.AuthenticatedChannelMessage.Companion
import id.walt.mdoc.cose.COSECryptoProvider
import id.walt.mdoc.cose.COSESign1
import id.walt.mdoc.cose.X5_CHAIN
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import org.bouncycastle.util.encoders.Hex
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Create simple COSE crypto provider for the given private and public key pairs. For verification only, private key can be omitted.
 * @param keys List of keys for this COSE crypto provider
 */
class AuthenticatedChannelCOSECryptoProvider(
    keys: List<AuthenticatedChannelCOSECryptoProviderKeyInfo>,
    verifierPublicKey: ECPublicKey
) : COSECryptoProvider {

    private val keyMap: Map<String, AuthenticatedChannelCOSECryptoProviderKeyInfo> = keys.associateBy { it.keyID }
    private val verifierKey = verifierPublicKey

    @OptIn(ExperimentalSerializationApi::class)
    override fun sign1(payload: ByteArray, keyID: String?): COSESign1 {
        val keyInfo = keyID?.let { keyMap[it] } ?: throw Exception("No key ID given, or key with given ID not found")
        val sign1Msg = AuthenticatedChannelMessage()
        sign1Msg.addAttribute(HeaderKeys.Algorithm, keyInfo.algorithmID.asCBOR(), Attribute.PROTECTED)
        if (keyInfo.x5Chain.size == 1) {
            CBORObject.FromObject(keyInfo.x5Chain.map { it.encoded }.reduceOrNull { acc, bytes -> acc + bytes })?.let {
                sign1Msg.addAttribute(
                    CBORObject.FromObject(X5_CHAIN),
                    it,
                    Attribute.UNPROTECTED
                )
            }
        } else {
            CBORObject.FromObject(keyInfo.x5Chain.map { CBORObject.FromObject(it.encoded) }.toTypedArray<CBORObject?>())
                ?.let {
                    sign1Msg.addAttribute(
                        CBORObject.FromObject(X5_CHAIN),
                        it,
                        Attribute.UNPROTECTED
                    )
                }
        }
        sign1Msg.SetContent(payload)
        sign1Msg.sign(verifierKey, keyInfo.privateKey as ECPrivateKey)

        val cborObj = sign1Msg.EncodeToCBORObject()
        println("Signed message: " + Hex.encode(cborObj.EncodeToBytes()))
        return Cbor.decodeFromByteArray<COSESign1>(cborObj.EncodeToBytes())
    }

    override fun verify1(coseSign1: COSESign1, keyID: String?): Boolean {
        val keyInfo = keyID?.let { keyMap[it] } ?: throw Exception("No key ID given, or key with given ID not found")
        val sign1Msg = Companion.DecodeFromBytes(coseSign1.toCBOR())
        return sign1Msg.validate(verifierKey, keyInfo.privateKey as ECPrivateKey)
    }

    private fun findRootCA(cert: X509Certificate, additionalTrustedRootCAs: List<X509Certificate>): X509Certificate? {
        val tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tm.init(null as? KeyStore)
        return tm.trustManagers
            .filterIsInstance<X509TrustManager>()
            .flatMap { it.acceptedIssuers.toList() }
            .plus(additionalTrustedRootCAs)
            .firstOrNull {
                cert.issuerX500Principal.name.equals(it.subjectX500Principal.name)
            }
    }

    private fun validateCertificateChain(
        certChain: List<X509Certificate>,
        keyInfo: AuthenticatedChannelCOSECryptoProviderKeyInfo
    ): Boolean {
        val certPath = CertificateFactory.getInstance("X509").generateCertPath(certChain)
        val cpv = CertPathValidator.getInstance("PKIX")
        val trustAnchorCert = findRootCA(certChain.last(), keyInfo.trustedRootCAs) ?: return false
        cpv.validate(certPath, PKIXParameters(setOf(TrustAnchor(trustAnchorCert, null))).apply {
            isRevocationEnabled = false
        })

        return true
    }

    override fun verifyX5Chain(coseSign1: COSESign1, keyID: String?): Boolean {
        val keyInfo = keyID?.let { keyMap[it] } ?: throw Exception("No key ID given, or key with given ID not found")
        return coseSign1.x5Chain?.let {
            val certChain = CertificateFactory.getInstance("X509").generateCertificates(ByteArrayInputStream(it))
                .map { it as X509Certificate }
            return certChain.isNotEmpty() && certChain.first().publicKey.encoded.contentEquals(keyInfo.publicKey.encoded) &&
                    validateCertificateChain(certChain.toList(), keyInfo)
        } ?: false
    }


}
