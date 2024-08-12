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

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.crypto.impl.ECDH
import com.nimbusds.jose.crypto.impl.HMAC
import com.nimbusds.jose.util.Base64URL
import net.jcip.annotations.ThreadSafe
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey


@ThreadSafe
class AuthenticatedChannelSigner(
    private val privateKey: PrivateKey,
    private val holderPublicKey: ECPublicKey
) : BaseJWSProvider(ALGORITHMS), JWSSigner {

    init {
        require("EC".equals(privateKey.algorithm, ignoreCase = true)) { "The private key algorithm must be EC" }
    }

    @Throws(JOSEException::class)
    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
        val alg = header.algorithm
        if (!supportedJWSAlgorithms().contains(alg)) {
            throw JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, this.supportedJWSAlgorithms()))
        } else {
            val hmac = try {
                val sharedSecret = ECDH.deriveSharedSecret(holderPublicKey, privateKey, null)
                val mac = HMAC.getInitMac("HmacSHA256", sharedSecret, null)
                mac.update(signingInput)

                mac.doFinal()
            } catch (e: Exception) {
                throw JOSEException(e.message, e)
            }

            return Base64URL.encode(hmac)
        }
    }

    companion object {
        val P256_ALGID = JWSAlgorithm("DVS-P256-SHA256-HS256")
        val P384_ALGID = JWSAlgorithm("DVS-P384-SHA256-HS256")
        val P512_ALGID = JWSAlgorithm("DVS-P512-SHA256-HS256")
        val ALGORITHMS = setOf(P256_ALGID, P384_ALGID, P512_ALGID)
    }
}
