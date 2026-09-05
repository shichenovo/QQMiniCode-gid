// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.github.shadowsocks.bg

/**
 * tun2proxy 的 JNI 桥接。
 *
 * 预编译的 libtun2proxy.so（Rust 实现的用户态 TCP/IP 栈，Reqable / shadowsocks-android
 * 同款方案）通过静态 JNI 符号导出：
 *   Java_com_github_shadowsocks_bg_Tun2proxy_run
 *   Java_com_github_shadowsocks_bg_Tun2proxy_stop
 * 因此 Kotlin 类必须放在 com.github.shadowsocks.bg 包下才能绑定。
 *
 * 工作方式：把 VpnService 建立的 TUN 文件描述符直接交给 Rust 侧，
 * tun2proxy 在用户态完成 TCP/IP 协议栈（重组、ACK、重传），
 * 并把每一条 TCP 连接以 SOCKS5 的形式转发给本地代理。
 */
object Tun2proxy {

    init {
        System.loadLibrary("tun2proxy")
    }

    /**
     * 在 TUN 上运行 tun2proxy（阻塞直到 stop 被调用或出错）。
     *
     * @param cliArgs 命令行参数，例如：
     *   "--tun-fd 42 --close-fd-on-drop true
     *    --proxy socks5://127.0.0.1:1080 --dns virtual --verbosity info"
     *   Android 上必须提供 --tun-fd 与 --dns。
     * @param tunMtu TUN 的 MTU，需与 VpnService.Builder.setMtu() 一致
     * @return 0 表示正常退出，非 0 为错误码
     */
    @JvmStatic
    external fun run(cliArgs: String, tunMtu: Char): Int

    /** 停止 tun2proxy，促使 [run] 返回。 */
    @JvmStatic
    external fun stop(): Int
}