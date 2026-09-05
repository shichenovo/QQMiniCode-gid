// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.crypto

import android.util.Base64 as AndroidBase64

/**
 * 简单 Base64 封装，统一编码方式。
 * Android 自带的 android.util.Base64 在主线程上执行小数据足够快。
 */
object Base64 {
    fun encode(data: ByteArray): String =
        AndroidBase64.encodeToString(data, AndroidBase64.NO_WRAP)

    fun decode(text: String): ByteArray =
        AndroidBase64.decode(text, AndroidBase64.DEFAULT)
}