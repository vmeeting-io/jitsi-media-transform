/*
 * Copyright @ 2018 - Present, 8x8 Inc
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
package org.jitsi.nlj.transform.node

import org.jitsi.config.JitsiConfig
import org.jitsi.metaconfig.config
import org.jitsi.metaconfig.from
import java.net.Inet4Address
import java.util.Random
import org.jitsi.nlj.PacketInfo
import org.jitsi.nlj.codec.vp8.Vp8Utils
import org.jitsi.nlj.rtp.VideoRtpPacket
import org.jitsi.utils.logging2.cinfo
import org.jitsi.utils.logging2.createChildLogger
import org.jitsi.utils.logging2.Logger
import org.jitsi_modified.impl.neomedia.codec.video.vp8.DePacketizer
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.EthernetPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV4Rfc1349Tos
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.UnknownPacket
import org.pcap4j.packet.namednumber.DataLinkType
import org.pcap4j.packet.namednumber.EtherType
import org.pcap4j.packet.namednumber.IpNumber
import org.pcap4j.packet.namednumber.IpVersion
import org.pcap4j.packet.namednumber.UdpPort
import org.pcap4j.util.MacAddress
import java.io.File

class VideoPcapWriter(
    parentLogger: Logger,
    filePath: String = "/tmp/${Random().nextLong()}.pcap"
) : ObserverNode("PCAP writer") {
    private val logger = createChildLogger(parentLogger)
    private val filePath = filePath
    private val filePathTmp = "$filePath.tmp"

    private val lazyHandle = lazy {
        Pcaps.openDead(DataLinkType.EN10MB, 65536)
    }
    private val handle by lazyHandle
    private val lazyWriter = lazy {
        logger.cinfo { "Pcap writer writing to file $filePath" }
        handle.dumpOpen(filePathTmp)
    }
    private val writer by lazyWriter

    private var videoSsrcToCap: Long? = null
    private val vp8PayloadType = 100
    private val resToCap = 180

    companion object {
        private val localhost = Inet4Address.getByName("127.0.0.1") as Inet4Address
    }

    override fun observe(packetInfo: PacketInfo) {
        val packet = packetInfo.packetAs<VideoRtpPacket>()
        // TODO: when VP9 is used, there will be only one stream, so we can remove this logic
        if (videoSsrcToCap == null &&
                packet.payloadType == vp8PayloadType &&
                DePacketizer.isKeyFrame(packet.buffer, packet.payloadOffset, packet.payloadLength) &&
                Vp8Utils.getHeightFromKeyFrame(packet) == resToCap) {
            videoSsrcToCap = packet.ssrc
        }
        // we need to capture rtx packets (payload type != vp8payloadtype) for gstreamer conversion to work
        if (videoSsrcToCap != packet.ssrc && packet.payloadType == vp8PayloadType) {
            return
        }

        val udpPayload = UnknownPacket.Builder()
        // We can't pass offset/limit values to udpPayload.rawData, so we need to create an array that contains
        // only exactly what we want to write
        val subBuf = ByteArray(packetInfo.packet.length)
        System.arraycopy(packetInfo.packet.buffer, packetInfo.packet.offset, subBuf, 0, packetInfo.packet.length)
        udpPayload.rawData(subBuf)
        val udp = UdpPacket.Builder()
                .srcPort(UdpPort(123, "blah"))
                .dstPort(UdpPort(456, "blah"))
                .srcAddr(localhost)
                .dstAddr(localhost)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(udpPayload)

        val ipPacket = IpV4Packet.Builder()
                .srcAddr(localhost)
                .dstAddr(localhost)
                .protocol(IpNumber.UDP)
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc1349Tos.newInstance(0))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(udp)

        val eth = EthernetPacket.Builder()
                .srcAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .type(EtherType.IPV4)
                .paddingAtBuild(true)
                .payloadBuilder(ipPacket)
                .build()

        writer.dump(eth)
    }

    override fun trace(f: () -> Unit) = f.invoke()

    fun close() {
        if (lazyWriter.isInitialized() && writer.isOpen) {
            writer.close()
        }

        if (lazyHandle.isInitialized() && handle.isOpen) {
            handle.close()
            renameFinalPcap(filePathTmp, filePath)
        }
    }

    private fun renameFinalPcap(oldFilePath: String, newFilePath: String): Boolean {
        val oldFile = File(oldFilePath)
        val newFile =  File(newFilePath)
        return oldFile.renameTo(newFile)
    }
}
