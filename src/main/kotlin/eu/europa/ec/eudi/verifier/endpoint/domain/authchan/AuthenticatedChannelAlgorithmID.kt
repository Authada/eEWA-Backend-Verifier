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

import COSE.CoseException
import com.upokecenter.cbor.CBORObject

enum class AuthenticatedChannelAlgorithmID(
    internal var value: CBORObject? = null,
    private var keySize: Int = 0,
    private var tagSize: Int = 0
) {
    `DVS-P256-SHA256-HS256`(-60),
    `DVS-P384-SHA256-HS256`(-61),
    `DVS-P512-SHA256-HS256`(-62),
    ;


    constructor(value: Int, cbitKey: Int = 0, cbitTag: Int = 0) : this(CBORObject.FromObject(value), cbitKey, cbitTag)

    fun asCBOR(): CBORObject? {
        return value
    }

    companion object {
        @Throws(CoseException::class)
        fun fromCBOR(obj: CBORObject?): AuthenticatedChannelAlgorithmID {
            if (obj == null) throw CoseException("No Algorithm Specified")
            for (alg in AuthenticatedChannelAlgorithmID.entries) {
                if (obj.equals(alg.value)) return alg
            }
            throw CoseException("Unknown Algorithm Specified")
        }
    }
}
