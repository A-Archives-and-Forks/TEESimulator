package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.Digest
import android.os.Binder
import android.os.Parcel
import android.os.RemoteException
import android.system.keystore2.IKeystoreOperation
import java.security.PrivateKey
import java.security.Signature
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * A software-only implementation of a cryptographic operation (e.g., signing). This class uses the
 * standard Java JCA to perform operations on a given private key.
 */
class SoftwareOperation(
    private val txId: Long,
    privateKey: PrivateKey,
    params: KeyMintAttestation,
) {
    private val signature: Signature

    init {
        // Parse the KeyMintAttestation object to determine the correct JCA algorithm string.
        val signatureAlgorithm = parseSignatureAlgorithm(params)
        SystemLogger.debug(
            "[SoftwareOp TX_ID: $txId] Initializing with algorithm: $signatureAlgorithm"
        )

        signature = Signature.getInstance(signatureAlgorithm).apply { initSign(privateKey) }
    }

    /**
     * Determines the JCA standard signature algorithm string from KeyMint parameters. Replicates
     * logic seen in AOSP frameworks like CertificateGenerator.
     */
    private fun parseSignatureAlgorithm(params: KeyMintAttestation): String {
        val digestName =
            when (params.digest.firstOrNull()) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                // Add other digest mappings as needed
                else -> "NONE" // A valid JCA value for certain algorithms
            }

        val algorithmName =
            when (params.algorithm) {
                Algorithm.EC -> "ECDSA"
                Algorithm.RSA -> "RSA"
                // Add other algorithm mappings as needed
                else ->
                    throw IllegalArgumentException(
                        "Unsupported algorithm for signing: ${params.algorithm}"
                    )
            }

        return "${digestName}with${algorithmName}"
    }

    fun update(data: ByteArray?) {
        if (data == null || data.isEmpty()) return
        try {
            signature.update(data)
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update signature.", e)
            throw e
        }
    }

    fun finish(data: ByteArray?): ByteArray {
        update(data)
        try {
            val result = signature.sign()
            SystemLogger.info(
                "[SoftwareOp TX_ID: $txId] Finished signing. Signature size: ${result.size} bytes."
            )
            return result
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish signing.", e)
            throw e
        }
    }

    fun abort() {
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }
}

/**
 * The Binder interface for our [SoftwareOperation].
 */
class SoftwareOperationBinder(private val operation: SoftwareOperation) : IKeystoreOperation.Stub() {

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? {
        operation.update(input)
        // As per the AIDL comments, the update method for a signing operation returns nothing.
        return null
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray {
        // The 'signature' parameter is for verification operations, so we ignore it here.
        return operation.finish(input)
    }

    @Throws(RemoteException::class)
    override fun abort() {
        operation.abort()
    }
}
