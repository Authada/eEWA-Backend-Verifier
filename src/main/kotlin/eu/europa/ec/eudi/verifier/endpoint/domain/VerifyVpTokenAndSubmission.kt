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
package eu.europa.ec.eudi.verifier.endpoint.domain

import COSE.AlgorithmID
import COSE.OneKey
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import cbor.Cbor
import com.jayway.jsonpath.JsonPath
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.prex.InputDescriptor
import eu.europa.ec.eudi.sdjwt.KeyBindingVerifier.MustBePresentAndValid
import eu.europa.ec.eudi.sdjwt.SdJwtVerifier
import eu.europa.ec.eudi.sdjwt.asClaims
import eu.europa.ec.eudi.sdjwt.asJwtVerifier
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationType.IdAndVpToken
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationType.IdTokenRequest
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationType.VpTokenRequest
import eu.europa.ec.eudi.verifier.endpoint.domain.authchan.AuthenticatedChannelAlgorithmID
import eu.europa.ec.eudi.verifier.endpoint.domain.authchan.AuthenticatedChannelAlgorithmID.`DVS-P256-SHA256-HS256`
import eu.europa.ec.eudi.verifier.endpoint.domain.authchan.AuthenticatedChannelCOSECryptoProvider
import eu.europa.ec.eudi.verifier.endpoint.domain.authchan.AuthenticatedChannelCOSECryptoProviderKeyInfo
import eu.europa.ec.eudi.verifier.endpoint.domain.authchan.AuthenticatedChannelSigner
import eu.europa.ec.eudi.verifier.endpoint.port.input.AuthorisationResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError.CredentialValidationFailed
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.cose.COSESign1
import id.walt.mdoc.cose.X5_CHAIN
import id.walt.mdoc.dataelement.ByteStringElement
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.issuersigned.IssuerSignedItem
import id.walt.mdoc.mdocauth.DeviceAuthentication
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.interfaces.ECPublicKey

private const val MSO_MDOC = "mso_mdoc"
private const val SD_JWT = "vc+sd-jwt"

@Serializable
data class CredentialEntry(
    val format: String,
    val credential: String
)

class VerifyVpTokenAndSubmission(
    private val verifierConfig: VerifierConfig
) {

    context(Raise<WalletResponseValidationError>)
    fun verify(
        responseObject: AuthorisationResponseTO,
        presentation: RequestObjectRetrieved
    ): List<CredentialEntry> {
        logger.info("VPToken: " + responseObject.vpToken)
        logger.info("PresentationSubmission " + responseObject.presentationSubmission)
        logger.info("APU " + responseObject.apu)
        logger.info("APV " + responseObject.apv)

        logger.info("Presentation Type " + presentation.type)
        val presentationDefinition = when (presentation.type) {
            is IdAndVpToken -> presentation.type.presentationDefinition
            is IdTokenRequest -> {
                return emptyList()
            }

            is VpTokenRequest -> presentation.type.presentationDefinition
        }
        logger.info("PresentationDefinition " + presentationDefinition)

        val presentationSubmission = responseObject.presentationSubmission!!

        val jsonPathReader = JsonPath.parse(responseObject.vpToken!!)

        return presentationDefinition.inputDescriptors.flatMap { id ->
            val matchingDescriptors = presentationSubmission.descriptorMaps.filter {
                id.id == it.id
            }
            matchingDescriptors.mapNotNull { matchingDescriptor ->
                val value =
                    jsonPathReader.read<String>(JsonPath.compile(matchingDescriptor.path.value))
                when (matchingDescriptor.format) {
                    MSO_MDOC -> {
                        val documentResponse =
                            Cbor.Default.decodeFromByteArray<DeviceResponse>(Base64URL.from(value).decode())
                        verifyMdocDocuments(
                            documentResponse,
                            presentation,
                            responseObject.apu!!,
                            responseObject.apv!!,
                            id
                        )
                    }

                    SD_JWT -> {
                        verifySdJwt(value, presentation, id)
                    }
                }
                CredentialEntry(format = matchingDescriptor.format, credential = value)
            }
        }
    }

    context(Raise<WalletResponseValidationError>)
    private fun verifyMdocFields(value: DeviceResponse, id: InputDescriptor) {
        value.documents.forEach {
            val nameSpaces = it.issuerSigned.nameSpaces
            ensure(!nameSpaces.isNullOrEmpty() && nameSpaces.containsKey(id.id.value)) {
                raise(CredentialValidationFailed)
            }
            val fieldsMap = mutableMapOf<String, JsonElement>()
            val properties = nameSpaces[id.id.value]!!.map { it.decode<IssuerSignedItem>() }.map {
                fieldsMap.put(it.elementIdentifier.value, JsonPrimitive(it.elementValue.toCBORHex()))
            }
            val documentMap = JsonObject(mapOf(id.id.value to JsonObject(fieldsMap)))

            val jsonPath = JsonPath.parse(Json.Default.encodeToString(JsonObject.serializer(), documentMap))
            id.constraints.fields().forEach { constraint ->
                if (constraint.optional.not()) {
                    properties.forEach { property ->
                        val foundProperty = constraint.paths.any {
                            !jsonPath.read<String>(it.value).isNullOrBlank()
                        }
                        ensure(foundProperty) {
                            raise(CredentialValidationFailed)
                        }
                    }
                }
            }
        }
    }


    context(Raise<WalletResponseValidationError>)
    fun verifyMdocDocuments(
        value: DeviceResponse,
        presentation: RequestObjectRetrieved,
        apu: Base64URL,
        apv: Base64URL,
        inputDescriptor: InputDescriptor
    ) {
        value.documents.forEach { mDoc ->
            validateMdoc(mDoc, presentation, apu, apv, inputDescriptor)
        }
        //TODO validate version
    }

    context(Raise<WalletResponseValidationError>)
    private fun validateMdoc(
        mDoc: MDoc,
        presentation: RequestObjectRetrieved,
        apu: Base64URL,
        apv: Base64URL,
        inputDescriptor: InputDescriptor
    ) {
        ensure(mDoc.verifyValidity()) {
            raise(CredentialValidationFailed)
        }
        ensure(mDoc.verifyDocType()) {
            raise(CredentialValidationFailed)
        }
        mDocCheckSignature(mDoc.issuerSigned.issuerAuth!!, presentation, inputDescriptor)
        mDocDeviceCheckSignature(mDoc, presentation, apu, apv)
    }


    context(Raise<WalletResponseValidationError>)
    private fun mDocDeviceCheckSignature(
        mdoc: MDoc,
        presentation: RequestObjectRetrieved,
        apu: Base64URL,
        apv: Base64URL
    ) {

        val deviceKeyInfo = mdoc.MSO!!.deviceKeyInfo
        val keyId = "default"
        val deviceCryptoPrvider =
            createCryptoProvider(
                OneKey(CBORObject.DecodeFromBytes(deviceKeyInfo.deviceKey.toCBOR())).AsPublicKey() as ECPublicKey,
                keyId
            )

        val sessTrans = Openid4VpUtils.generateSessionTranscript(
            presentation.clientIdSchemeOverride?.clientId ?: verifierConfig.clientIdScheme.clientId,
            verifierConfig.responseUriBuilder(presentation.requestId).toExternalForm(),
            apv.decodeToString(),
            apu.decodeToString(),
        )

        val result = mdoc.verifyDeviceSignature(
            DeviceAuthentication(
                Cbor.Default.decodeFromByteArray(sessTrans),
                mdoc.MSO!!.docType.value,
                mdoc.deviceSigned!!.nameSpaces
            ),
            deviceCryptoPrvider,
            keyId
        )

        logger.info("Mdoc device Signature valid = $result")
        ensure(result) {
            raise(CredentialValidationFailed)
        }
    }

    context(Raise<WalletResponseValidationError>)
    private fun mDocCheckSignature(
        auth: COSESign1,
        presentation: RequestObjectRetrieved,
        inputDescriptor: InputDescriptor
    ) {
        val isAuthenticatedChannel = auth.algorithm in
                AuthenticatedChannelAlgorithmID.entries.map { it.value!!.AsInt32() }

        logger.info("Used rp_eph key : ${presentation.ephemeralEcPrivateKey?.value}")
        val verifierKeys = JWK.parse(presentation.ephemeralEcPrivateKey!!.value)
        val singleCert = auth.getLeafCertificate()
        val publicKey = X509CertUtils.parse(singleCert).publicKey as ECPublicKey
        val authChanChecks = inputDescriptor.format?.let { format ->
            format.jsonObject()[MSO_MDOC]?.jsonObject!!["alg"]?.jsonArray?.map {
                it.jsonPrimitive.content.startsWith("DVS-")
            }
        } ?: listOf(true, false)
        val result = if (isAuthenticatedChannel) {
            if (!authChanChecks.contains(true)) {
                logger.error("Authenticated channel is used but not allowed")
                raise(CredentialValidationFailed)
            }
            val cryptoProvider = createCryptoProviderAuthChan(
                verifierKeys.toECKey(),
                publicKey
            )
            val result = cryptoProvider.verify1(auth, verifierKeys.keyID)
            logger.info("mdoc Authenticated channel valid = $result")
            result
        } else {
            if (!authChanChecks.contains(false)) {
                logger.error("Signature is used but not allowed")
                raise(CredentialValidationFailed)
            }
            val keyId = "default"
            val result = createCryptoProvider(
                publicKey,
                keyId
            ).verify1(auth, keyId)
            logger.info("Mdoc Signature valid = $result")
            result
        }
        ensure(result) {
            raise(CredentialValidationFailed)
        }
    }

    fun COSESign1.getLeafCertificate(): ByteArray {
        val unprotectedHeader = data[1] as? MapElement
            ?: throw SerializationException("Missing COSE_Sign1 unprotected header")
        return when (val headerParameter = unprotectedHeader.value[MapKey(X5_CHAIN)]) {
            is ByteStringElement -> headerParameter.value
            is ListElement -> {
                headerParameter.value.map { (it as? ByteStringElement)?.value ?: ByteArray(0) }.toTypedArray()
                    .first()
            }

            else -> throw IllegalStateException()
        }
    }

    context(Raise<WalletResponseValidationError>)
    fun verifySdJwt(
        value: String,
        presentationRequest: RequestObjectRetrieved,
        inputDescriptor: InputDescriptor
    ) {
        logger.info("trying to validate sd-jwt with value: $value")
        val claims = SdJwtVerifier.verifyPresentation(
            { unverifiedJwt ->
                try {
                    logger.info("parsing signed jwt")
                    val parsedJwt = SignedJWT.parse(unverifiedJwt)
                    val issuerJwk = parsedJwt.header.jwk
                    val isAuthenticatedChannel = (parsedJwt.header.algorithm in AuthenticatedChannelSigner.ALGORITHMS)
                    logger.info("is authenticated channel: $isAuthenticatedChannel")

                    val authChanChecks = inputDescriptor.format?.let { format ->
                        format.jsonObject()[SD_JWT]?.jsonObject!!["sd-jwt_alg_values"]?.jsonArray?.map {
                            it.jsonPrimitive.content.startsWith("DVS-")
                        }
                    } ?: listOf(true, false)

                    val valid = if (isAuthenticatedChannel) {
                        if (!authChanChecks.contains(true)) {
                            logger.error("Authenticated channel is used but not allowed")
                            raise(CredentialValidationFailed)
                        }
                        val hmacResult = AuthenticatedChannelSigner(
                            JWK.parse(presentationRequest.ephemeralEcPrivateKey!!.value).toECKey().toECPrivateKey(),
                            issuerJwk.toECKey().toECPublicKey()
                        )
                            .sign(parsedJwt.header, parsedJwt.signingInput)
                        val validHmac = parsedJwt.signature.equals(hmacResult)
                        logger.info("sd-jwt valid authenticated channel = ${validHmac}")
                        logger.info("sd-jwt chain ${parsedJwt.header.x509CertChain}")
                        validHmac
                    } else {
                        if (!authChanChecks.contains(false)) {
                            logger.error("Signature is used but not allowed")
                            raise(CredentialValidationFailed)
                        }
                        logger.info("checking signature")
                        val verifier = ECDSAVerifier(issuerJwk.toECKey())
                        logger.info("sd-jwt verifier created")
                        parsedJwt.verify(verifier)
                    }
                    if (!valid) {
                        logger.info("sd-jwt is invalid")
                        raise(CredentialValidationFailed)
                    }
                    logger.info("sd-jwt validated")
                    parsedJwt.jwtClaimsSet.asClaims()
                } catch (e: Exception) {
                    logger.error("error validating sd-jwt", e)
                    raise(CredentialValidationFailed)
                }
            },
            MustBePresentAndValid { claims ->
                logger.info("creating kb-jwt verifier")
                val jwkObject = claims["cnf"]?.jsonObject?.get("jwk")?.jsonObject
                logger.info("kb jwk :" + jwkObject)
                jwkObject?.let {
                    ECDSAVerifier(
                        JWK.parse(Json.Default.encodeToString<JsonObject>(jwkObject)).toECKey()
                            .toECPublicKey()
                    ).asJwtVerifier()
                } ?: throw IllegalStateException("Missing jwk header property")
            },
            value
        ).getOrElse {
            logger.error("error validating kb-jwt", it)
            null
        }

        ensureNotNull(claims) {
            logger.info("kb-jwt is invalid")
            raise(CredentialValidationFailed)
        }
        logger.info("sd-jwt and kb-jwt validated")

    }

    private fun createCryptoProviderAuthChan(
        key: ECKey,
        issuerPublicKey: ECPublicKey,
    ): AuthenticatedChannelCOSECryptoProvider = AuthenticatedChannelCOSECryptoProvider(
        listOf(
            AuthenticatedChannelCOSECryptoProviderKeyInfo(
                keyID = key.keyID,
                algorithmID = `DVS-P256-SHA256-HS256`,
                publicKey = key.toECPublicKey(),
                privateKey = key.toECPrivateKey(),
                trustedRootCAs = emptyList(),
            ),
        ),
        issuerPublicKey
    )

    private fun createCryptoProvider(
        key: ECPublicKey,
        keyId: String,
    ): SimpleCOSECryptoProvider = SimpleCOSECryptoProvider(
        listOf(
            COSECryptoProviderKeyInfo(
                keyID = keyId,
                algorithmID = AlgorithmID.ECDSA_256,
                publicKey = key,
                privateKey = null,
                trustedRootCAs = emptyList(),
            ),
        ),
    )

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(VerifyVpTokenAndSubmission::class.java)
    }
}
