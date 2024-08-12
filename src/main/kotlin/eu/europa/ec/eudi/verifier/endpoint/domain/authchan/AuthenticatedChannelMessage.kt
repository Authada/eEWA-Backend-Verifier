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
import COSE.Message
import COSE.MessageTag.Sign1
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.impl.ECDH
import com.nimbusds.jose.crypto.impl.HMAC
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType.Array
import com.upokecenter.cbor.CBORType.ByteString
import com.upokecenter.cbor.CBORType.Map
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Arrays

class AuthenticatedChannelMessage @JvmOverloads constructor(emitTag: Boolean = true, emitContent: Boolean = true) :
    Message() {
    private var rgbSignature: ByteArray? = null
    private val contextString: String = "Signature1"

    init {
        this.emitTag = emitTag
        this.emitContent = emitContent
        this.messageTag = Sign1
    }

    @Throws(CoseException::class)
    fun sign(publicKey: ECPublicKey, privateKey: ECPrivateKey) {
        if (rgbContent == null) throw CoseException("No Content Specified")
        if (rgbSignature != null) return

        if (rgbProtected == null) {
            rgbProtected = if (objProtected.size() > 0) objProtected.EncodeToBytes()
            else ByteArray(0)
        }

        val obj = CBORObject.NewArray()
        obj.Add(contextString)
        obj.Add(rgbProtected)
        obj.Add(externalData)
        obj.Add(rgbContent)

        rgbSignature = computeSignature(obj.EncodeToBytes(), publicKey, privateKey)

        ProcessCounterSignatures()
    }

    fun computeSignature(bytes: ByteArray, publicKey: ECPublicKey, privateKey: ECPrivateKey): ByteArray {
        val hmac = try {
            val sharedSecret = ECDH.deriveSharedSecret(publicKey, privateKey, null)
            val mac = HMAC.getInitMac("HmacSHA256", sharedSecret, null)
            mac.update(bytes)
            mac.doFinal()
        } catch (e: Exception) {
            throw JOSEException(e.message, e)
        }

        return hmac
    }

    @Throws(CoseException::class)
    fun validate(publicKey: ECPublicKey, privateKey: ECPrivateKey): Boolean {
        assert(rgbSignature != null)
        val obj = CBORObject.NewArray()
        obj.Add(contextString)
        if (objProtected.size() > 0) obj.Add(rgbProtected)
        else obj.Add(CBORObject.FromObject(ByteArray(0)))
        obj.Add(externalData)
        obj.Add(rgbContent)
        return validateSignature(obj.EncodeToBytes(), rgbSignature!!, publicKey, privateKey)
    }

    private fun validateSignature(
        encodeToBytes: ByteArray,
        rgbSignature: ByteArray,
        publicKey: ECPublicKey,
        privateKey: ECPrivateKey
    ): Boolean {
        val signature = computeSignature(encodeToBytes, publicKey, privateKey)
        return Arrays.equals(rgbSignature, signature)
    }

    @Throws(CoseException::class)
    override fun DecodeFromCBORObject(messageObject: CBORObject) {
        if (messageObject.size() != 4) throw CoseException("Invalid Sign1 structure")

        if (messageObject[0].type == ByteString) {
            rgbProtected = messageObject[0].GetByteString()
            if (messageObject[0].GetByteString().size == 0) objProtected = CBORObject.NewMap()
            else {
                objProtected = CBORObject.DecodeFromBytes(rgbProtected)
                if (objProtected.size() == 0) rgbProtected = ByteArray(0)
            }
        } else throw CoseException("Invalid Sign1 structure")

        if (messageObject[1].type == Map) {
            objUnprotected = messageObject[1]
        } else throw CoseException("Invalid Sign1 structure")

        if (messageObject[2].type == ByteString) rgbContent = messageObject[2].GetByteString()
        else if (!messageObject[2].isNull) throw CoseException("Invalid Sign1 structure")

        if (messageObject[3].type == ByteString) rgbSignature = messageObject[3].GetByteString()
        else throw CoseException("Invalid Sign1 structure")
    }

    @Throws(CoseException::class)
    override fun EncodeCBORObject(): CBORObject {
        if (rgbSignature == null) throw CoseException("sign function not called")
        if (rgbProtected == null) throw CoseException("Internal Error")

        val obj = CBORObject.NewArray()
        obj.Add(rgbProtected)
        obj.Add(objUnprotected)
        if (emitContent) obj.Add(rgbContent)
        else obj.Add(null)
        obj.Add(rgbSignature)

        return obj
    }

    companion object {
        @Throws(CoseException::class)
        fun DecodeFromBytes(rgbData: ByteArray?): AuthenticatedChannelMessage {
            val messageObject = CBORObject.DecodeFromBytes(rgbData)

            if (messageObject.type != Array) throw CoseException("Message is not a COSE security Message")

            if (messageObject.isTagged) {
                if (messageObject.GetAllTags().size != 1) throw CoseException("Malformed message - too many tags")
            }

            val msg = AuthenticatedChannelMessage()
            msg.DecodeFromCBORObject(messageObject)
            return msg
        }
    }
}
