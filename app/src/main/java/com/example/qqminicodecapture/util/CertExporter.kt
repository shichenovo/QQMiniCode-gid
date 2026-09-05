// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.util

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/**
 * 证书导出工具
 *
 * 把 App 自签 CA 证书的 PEM 内容写入用户可见的 Download 目录。
 *
 * 适配规则：
 *  - Android 10 (Q) 及以下：直接写入 Environment.getExternalStoragePublicDirectory(Download)
 *  - Android 11+ (API 30+)：使用 MediaStore.Downloads 写入，无需 WRITE_EXTERNAL_STORAGE 权限
 *  - Android 14+ (API 34+)：MediaStore.Downloads 仍然有效（推荐方案）
 *  - Android 17 (API 37+)：与上述一致，必要时配合 scoped storage 校验
 */
object CertExporter {

    private const val TAG = "CertExporter"
    private const val FILE_NAME = "QQMiniCodeCapture-CA.pem"
    private const val MIME      = "application/x-pem-file"

    /**
     * @return 写入后的 Uri（成功）或 null（失败）
     */
    fun exportToDownloads(context: Context, pemContent: String): Uri? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            exportViaMediaStore(context, pemContent)
        } else {
            exportLegacy(context, pemContent)
        }
    }

    /**
     * Android 10+ 使用 MediaStore Downloads 集合（推荐）
     */
    private fun exportViaMediaStore(context: Context, pemContent: String): Uri? {
        val resolver = context.contentResolver
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI

        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, FILE_NAME)
            put(MediaStore.Downloads.MIME_TYPE, MIME)
            put(MediaStore.Downloads.IS_PENDING, 1)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
        }

        val uri = resolver.insert(collection, values) ?: run {
            Log.e(TAG, "MediaStore insert returned null")
            return null
        }
        try {
            resolver.openOutputStream(uri)?.use { out ->
                out.write(pemContent.toByteArray(Charsets.UTF_8))
                out.flush()
            }
            // 标记 pending = 0
            val update = ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }
            resolver.update(uri, update, null, null)
            Log.i(TAG, "Cert saved to $uri")
            return uri
        } catch (t: Throwable) {
            Log.e(TAG, "MediaStore write failed", t)
            try { resolver.delete(uri, null, null) } catch (_: Throwable) {}
            return null
        }
    }

    /**
     * 兼容 Android 9 及以下
     */
    private fun exportLegacy(context: Context, pemContent: String): Uri? {
        return try {
            @Suppress("DEPRECATION")
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (!dir.exists()) dir.mkdirs()
            val f = File(dir, FILE_NAME)
            FileOutputStream(f).use { it.write(pemContent.toByteArray(Charsets.UTF_8)) }
            Uri.fromFile(f)
        } catch (t: Throwable) {
            Log.e(TAG, "Legacy export failed", t)
            null
        }
    }
}