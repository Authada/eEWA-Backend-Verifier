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

import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represent the [WalletResponse] as returned by the wallet
 */
@Serializable
@SerialName("wallet_response")
data class WalletResponseTO(
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("credentials") val credentials: List<CredentialEntry>? = null,
    @SerialName("presentation_submission") val presentationSubmission: PresentationSubmission? = null,
    @SerialName("error") val error: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
)

private fun WalletResponse.toTO(): WalletResponseTO {
    return when (this) {
        is WalletResponse.IdToken -> WalletResponseTO(idToken = idToken)
        is WalletResponse.VpToken -> WalletResponseTO(
            credentials = credentials,
            presentationSubmission = presentationSubmission,
        )
        is WalletResponse.IdAndVpToken -> WalletResponseTO(
            idToken = idToken,
            credentials = credentials,
            presentationSubmission = presentationSubmission,
        )
        is WalletResponse.Error -> WalletResponseTO(
            error = value,
            errorDescription = description,
        )
    }
}

/**
 * Given a [TransactionId] and a [Nonce] returns the [WalletResponse]
 */
fun interface GetWalletResponse {
    suspend operator fun invoke(transactionId: TransactionId, responseCode: ResponseCode?): QueryResponse<WalletResponseTO>
}

class GetWalletResponseLive(
    private val loadPresentationById: LoadPresentationById,
) : GetWalletResponse {
    override suspend fun invoke(transactionId: TransactionId, responseCode: ResponseCode?): QueryResponse<WalletResponseTO> {
        return when (val presentation = loadPresentationById(transactionId)) {
            null -> NotFound
            is Presentation.Submitted ->
                when {
                    presentation.responseCode != null && responseCode == null -> InvalidState
                    presentation.responseCode == null && responseCode != null -> InvalidState
                    presentation.responseCode == null && responseCode == null -> Found(presentation.walletResponse.toTO())
                    presentation.responseCode == responseCode -> Found(presentation.walletResponse.toTO())
                    else -> InvalidState
                }
            else -> InvalidState
        }
    }
}
