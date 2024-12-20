/*
 * Copyright (c) 2023 European Commission
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
 *
 * Modified by AUTHADA GmbH
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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.verifier.endpoint.domain.EphemeralEncryptionKeyPairJWK
import eu.europa.ec.eudi.verifier.endpoint.domain.JarmOption
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.port.input.AuthorisationResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Decrypts an encrypted JWT and maps the JWT claimSet to an AuthorisationResponseTO
 */
object VerifyJarmEncryptedJwtNimbus : VerifyJarmJwtSignature {

    private val logger: Logger = LoggerFactory.getLogger(VerifyJarmEncryptedJwtNimbus::class.java)

    override fun invoke(
        jarmOption: JarmOption,
        ephemeralEcPrivateKey: EphemeralEncryptionKeyPairJWK?,
        jarmJwt: Jwt,
    ): Result<AuthorisationResponseTO> = runCatching {
        processor(jarmOption, ephemeralEcPrivateKey)
            .process(jarmJwt, null)
            .run {
                val header = EncryptedJWT.parse(jarmJwt).header
                logger.info("Response header + $header")
                mapToDomain(header.agreementPartyVInfo, header.agreementPartyUInfo)
            }

    }

    private fun processor(
        jarmOption: JarmOption,
        ephemeralEcPrivateKey: EphemeralEncryptionKeyPairJWK?,
    ): JWTProcessor<SecurityContext> {
        return when (jarmOption) {
            is JarmOption.Signed -> error("Signed not supported yet")
            is JarmOption.Encrypted -> {
                require(ephemeralEcPrivateKey != null) { "Missing decryption key" }
                encryptedProcessor(jarmOption, ephemeralEcPrivateKey)
            }

            is JarmOption.SignedAndEncrypted -> error("SignedAndEncrypted not supported yet")
        }
    }

    private fun encryptedProcessor(
        encrypt: JarmOption.Encrypted,
        ephemeralEcPrivateKey: EphemeralEncryptionKeyPairJWK,
    ): JWTProcessor<SecurityContext> = DefaultJWTProcessor<SecurityContext>().apply {
        jweKeySelector = JWEDecryptionKeySelector(
            encrypt.nimbusJWSAlgorithm(),
            encrypt.nimbusEnc(),
            ImmutableJWKSet(JWKSet(ephemeralEcPrivateKey.jwk())),
        )
    }

    private fun JWTClaimsSet.mapToDomain(agreementPartyVInfo: Base64URL?, agreementPartyUInfo: Base64URL?): AuthorisationResponseTO =
        AuthorisationResponseTO(
            state = getClaim("state")?.toString(),
            idToken = getClaim("id_token")?.toString(),
            vpToken = getClaim("vp_token")?.toString(),
            presentationSubmission = getJSONObjectClaim("presentation_submission")?.let {
                val json = Gson().toJson(it)
                logger.debug("presentation_submission: $json")
                PresentationExchange.jsonParser.decodePresentationSubmission(json).getOrThrow()
            },
            error = getClaim("error")?.toString(),
            errorDescription = getClaim("error_description")?.toString(),
            apu =  agreementPartyUInfo,
            apv =  agreementPartyVInfo,
        )
}
