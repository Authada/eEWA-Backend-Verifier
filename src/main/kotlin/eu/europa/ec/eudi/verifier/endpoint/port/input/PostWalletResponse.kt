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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.None
import arrow.core.Option
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.some
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.Clock

/**
 * Represent the Authorisation Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val idToken: String? = null,
    val vpToken: String? = null,
    val presentationSubmission: PresentationSubmission? = null,
    val apu: Base64URL? = null,
    val apv: Base64URL? = null
)

sealed interface AuthorisationResponse {

    data class DirectPost(val response: AuthorisationResponseTO) : AuthorisationResponse
    data class DirectPostJwt(val state: String?, val jarm: Jwt) : AuthorisationResponse
}

sealed interface WalletResponseValidationError {
    data object MissingState : WalletResponseValidationError
    data object CredentialValidationFailed : WalletResponseValidationError
    data class PresentationDefinitionNotFound(val requestId: RequestId) : WalletResponseValidationError

    data class UnexpectedResponseMode(
        val requestId: RequestId,
        val expected: ResponseModeOption,
        val actual: ResponseModeOption,
    ) : WalletResponseValidationError

    data class PresentationNotInExpectedState(val requestId: RequestId) : WalletResponseValidationError

    data object IncorrectStateInJarm : WalletResponseValidationError
    data object MissingIdToken : WalletResponseValidationError
    data object MissingVpTokenOrPresentationSubmission : WalletResponseValidationError
}

context(Raise<WalletResponseValidationError>)
internal fun AuthorisationResponseTO.toDomain(
    presentation: RequestObjectRetrieved,
    resultDocuments: List<CredentialEntry>
): WalletResponse {
    fun requiredIdToken(): WalletResponse.IdToken {
        ensureNotNull(idToken) { WalletResponseValidationError.MissingIdToken }
        return WalletResponse.IdToken(idToken)
    }

    fun requiredVpToken(): WalletResponse.VpToken {
        ensureNotNull(vpToken) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        ensureNotNull(presentationSubmission) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        return WalletResponse.VpToken(resultDocuments, presentationSubmission)
    }

    fun requiredIdAndVpToken(): WalletResponse.IdAndVpToken {
        val a = requiredIdToken()
        val b = requiredVpToken()
        return WalletResponse.IdAndVpToken(a.idToken, resultDocuments, b.presentationSubmission)
    }

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }

    return maybeError ?: when (presentation.type) {
        is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken().idToken)
        is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
            requiredVpToken().credentials,
            requiredVpToken().presentationSubmission,
        )

        is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
            requiredIdAndVpToken().idToken,
            requiredIdAndVpToken().credentials,
            requiredIdAndVpToken().presentationSubmission,
        )
    }
}

@Serializable
data class WalletResponseAcceptedTO(
    @SerialName("redirect_uri") val redirectUri: String,
)

/**
 * This is use case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
fun interface PostWalletResponse {

    context(Raise<WalletResponseValidationError>)
    suspend operator fun invoke(walletResponse: AuthorisationResponse): Option<WalletResponseAcceptedTO>
}

class PostWalletResponseLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val verifyJarmJwtSignature: VerifyJarmJwtSignature,
    private val clock: Clock,
    private val verifierConfig: VerifierConfig,
    private val generateResponseCode: GenerateResponseCode,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val verifyVpTokenAndSubmission: VerifyVpTokenAndSubmission,
) : PostWalletResponse {

    context(Raise<WalletResponseValidationError>)
    override suspend operator fun invoke(walletResponse: AuthorisationResponse): Option<WalletResponseAcceptedTO> {
        val presentation = loadPresentation(walletResponse)

        // Verify the AuthorisationResponse matches what is expected for the Presentation
        val responseMode = walletResponse.responseMode()
        ensure(presentation.responseMode == responseMode) {
            WalletResponseValidationError.UnexpectedResponseMode(
                presentation.requestId,
                expected = presentation.responseMode,
                actual = responseMode,
            )
        }

        val responseObject = responseObject(walletResponse, presentation)
        val resultDocuments = verifyVpTokenAndSubmission.verify(responseObject, presentation)
        val submitted = submit(presentation, responseObject, resultDocuments).also { storePresentation(it) }

        return when (val getWalletResponseMethod = presentation.getWalletResponseMethod) {
            is GetWalletResponseMethod.Redirect ->
                with(createQueryWalletResponseRedirectUri) {
                    requireNotNull(submitted.responseCode) { "ResponseCode expected in Submitted state but not found" }
                    val redirectUri = getWalletResponseMethod.redirectUri(submitted.responseCode)
                    WalletResponseAcceptedTO(redirectUri.toExternalForm()).some()
                }

            GetWalletResponseMethod.Poll -> None
        }
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun loadPresentation(walletResponse: AuthorisationResponse): RequestObjectRetrieved {
        val state = when (walletResponse) {
            is AuthorisationResponse.DirectPost -> walletResponse.response.state
            is AuthorisationResponse.DirectPostJwt -> walletResponse.state
        }
        ensureNotNull(state) { WalletResponseValidationError.MissingState }
        val requestId = RequestId(state)

        val presentation = loadPresentationByRequestId(requestId)
        ensureNotNull(presentation) { WalletResponseValidationError.PresentationDefinitionNotFound(requestId) }
        ensure(presentation is RequestObjectRetrieved) {
            WalletResponseValidationError.PresentationNotInExpectedState(
                requestId,
            )
        }
        return presentation
    }

    context(Raise<WalletResponseValidationError>)
    private fun responseObject(
        walletResponse: AuthorisationResponse,
        presentation: RequestObjectRetrieved,
    ): AuthorisationResponseTO = when (walletResponse) {
        is AuthorisationResponse.DirectPost -> walletResponse.response
        is AuthorisationResponse.DirectPostJwt -> {
            val response = verifyJarmJwtSignature(
                jarmOption = verifierConfig.clientMetaData.jarmOption,
                ephemeralEcPrivateKey = presentation.ephemeralEcPrivateKey,
                jarmJwt = walletResponse.jarm,
            ).getOrThrow()
            ensure(response.state == walletResponse.state) { WalletResponseValidationError.IncorrectStateInJarm }
            response
        }
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
        resultDocuments: List<CredentialEntry>
    ): Presentation.Submitted {
        // add the wallet response to the presentation
        val walletResponse = responseObject.toDomain(presentation,resultDocuments)
        val responseCode = when (presentation.getWalletResponseMethod) {
            GetWalletResponseMethod.Poll -> null
            is GetWalletResponseMethod.Redirect -> generateResponseCode()
        }
        return presentation.submit(clock, walletResponse, responseCode).getOrThrow()
    }
}

/**
 * Gets the [ResponseModeOption] that corresponds to the receiver [AuthorisationResponse].
 */
private fun AuthorisationResponse.responseMode(): ResponseModeOption = when (this) {
    is AuthorisationResponse.DirectPost -> ResponseModeOption.DirectPost
    is AuthorisationResponse.DirectPostJwt -> ResponseModeOption.DirectPostJwt
}
