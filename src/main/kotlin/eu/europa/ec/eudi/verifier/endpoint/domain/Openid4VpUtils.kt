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

package eu.europa.ec.eudi.verifier.endpoint.domain

import com.upokecenter.cbor.CBORObject
import java.security.MessageDigest

/**
 *  Utility class to generate the session transcript for the OpenID4VP protocol.
 *
 *  SessionTranscript = [
 *    DeviceEngagementBytes,
 *    EReaderKeyBytes,
 *    Handover
 *  ]
 *
 *  DeviceEngagementBytes = null,
 *  EReaderKeyBytes = null
 *
 *  Handover = OID4VPHandover
 *  OID4VPHandover = [
 *    clientIdHash
 *    responseUriHash
 *    nonce
 *  ]
 *
 *  clientIdHash = bstr
 *  responseUriHash = bstr
 *
 *  where clientIdHash is the SHA-256 hash of clientIdToHash and responseUriHash is the SHA-256 hash of the responseUriToHash.
 *
 *
 *  clientIdToHash = [clientId, mdocGeneratedNonce]
 *  responseUriToHash = [responseUri, mdocGeneratedNonce]
 *
 *
 *  mdocGeneratedNonce = tstr
 *  clientId = tstr
 *  responseUri = tstr
 *  nonce = tstr
 *
 */

internal object Openid4VpUtils {

    @JvmStatic
    internal fun generateSessionTranscript(
        clientId: String,
        responseUri: String,
        nonce: String,
        mdocGeneratedNonce: String
    ): ByteArray {

        val openID4VPHandover =
            generateOpenId4VpHandover(clientId, responseUri, nonce, mdocGeneratedNonce)

        val sessionTranscriptBytes =
            CBORObject.NewArray().apply {
                Add(CBORObject.Null)
                Add(CBORObject.Null)
                Add(openID4VPHandover)
            }.EncodeToBytes()

        return sessionTranscriptBytes
    }

    @JvmStatic
    internal fun generateOpenId4VpHandover(
        clientId: String,
        responseUri: String,
        nonce: String,
        mdocGeneratedNonce: String
    ): CBORObject {
        val clientIdToHash = CBORObject.NewArray().apply {
            Add(clientId)
            Add(mdocGeneratedNonce)
        }.EncodeToBytes()

        val responseUriToHash = CBORObject.NewArray().apply {
            Add(responseUri)
            Add(mdocGeneratedNonce)
        }.EncodeToBytes()

        val clientIdHash = MessageDigest.getInstance("SHA-256").digest(clientIdToHash)
        val responseUriHash = MessageDigest.getInstance("SHA-256").digest(responseUriToHash)

        val openID4VPHandover = CBORObject.NewArray().apply {
            Add(clientIdHash)
            Add(responseUriHash)
            Add(nonce)
        }
        return openID4VPHandover
    }
}
