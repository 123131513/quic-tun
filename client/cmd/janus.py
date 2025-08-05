import argparse
import asyncio
import logging
import random
import string
import time

import aiohttp
from aiortc import RTCPeerConnection, RTCSessionDescription, VideoStreamTrack
from aiortc.contrib.media import MediaPlayer, MediaRecorder
from aiortc import RTCRtpSender
from aiortc.rtcrtpsender import RTCRtpSendParameters, RTCRtpCodecParameters
from aiortc import RTCRtcpParameters
from aiortc.rtcrtpparameters import RTCRtpEncodingParameters, RTCRtpHeaderExtensionParameters
from aiortc.codecs import vpx

pcs = set()

# 用于后续发送 offer 的上下文缓存
last_media_config = {}

def transaction_id():
    return "".join(random.choice(string.ascii_letters) for x in range(12))


class JanusPlugin:
    def __init__(self, session, url):
        self._queue = asyncio.Queue()
        self._session = session
        self._url = url

    async def send(self, payload):
        message = {"janus": "message", "transaction": transaction_id()}
        message.update(payload)
        async with self._session._http.post(self._url, json=message) as response:
            data = await response.json()
            assert data["janus"] == "ack"

        response = await self._queue.get()
        assert response["transaction"] == message["transaction"]
        return response


class JanusSession:
    def __init__(self, url):
        self._http = None
        self._poll_task = None
        self._plugins = {}
        self._root_url = url
        self._session_url = None
        self._slowlink_count = 0
        self._last_slowlink_ts = time.time()
        self._bitrate = 10_000_000  # 初始码率
        self._min_bitrate = 5_000_000
        self._pc = None  # 后续设置为 RTCPeerConnection
        self._plugin = None  # 设置为 JanusPlugin
        self._media = {"audio": False, "video": True}

    async def attach(self, plugin_name: str) -> JanusPlugin:
        message = {
            "janus": "attach",
            "plugin": plugin_name,
            "transaction": transaction_id(),
        }
        async with self._http.post(self._session_url, json=message) as response:
            data = await response.json()
            assert data["janus"] == "success"
            plugin_id = data["data"]["id"]
            plugin = JanusPlugin(self, self._session_url + "/" + str(plugin_id))
            self._plugins[plugin_id] = plugin
            return plugin

    async def create(self):
        self._http = aiohttp.ClientSession()
        message = {"janus": "create", "transaction": transaction_id()}
        async with self._http.post(self._root_url, json=message) as response:
            data = await response.json()
            assert data["janus"] == "success"
            session_id = data["data"]["id"]
            self._session_url = self._root_url + "/" + str(session_id)

        self._poll_task = asyncio.ensure_future(self._poll())

    async def destroy(self):
        if self._poll_task:
            self._poll_task.cancel()
            self._poll_task = None

        if self._session_url:
            message = {"janus": "destroy", "transaction": transaction_id()}
            async with self._http.post(self._session_url, json=message) as response:
                data = await response.json()
                assert data["janus"] == "success"
            self._session_url = None

        if self._http:
            await self._http.close()
            self._http = None

    async def _poll(self):
        while True:
            params = {"maxev": 1, "rid": int(time.time() * 1000)}
            async with self._http.get(self._session_url, params=params) as response:
                data = await response.json()
                if data.get("janus") == "event":
                    plugin = self._plugins.get(data["sender"], None)
                    if plugin:
                        await plugin._queue.put(data)
                    if data.get("media"):
                        medium = next(iter(data["media"]))
                        state = data["media"][medium]
                        mid = data["media"].get("mid", "unknown")
                        print(f"[mediaState] {medium} {'started' if state == 'on' else 'stopped'} (mid={mid})")
                    if data.get("slow_link"):
                        slow = data["slow_link"]
                        uplink = slow.get("uplink", False)
                        lost = slow.get("lost", 0)
                        mid = slow.get("mid", "unknown")
                        print(f"[slowLink] {'Sending' if uplink else 'Receiving'} issues on mid={mid}, lost={lost} packets")

                        now = time.time()
                        if not uplink and self._pc and self._plugin:
                            # 记录 slowlink 次数
                            if now - self._last_slowlink_ts < 10:  # 10 秒内重复
                                self._slowlink_count += 1
                            else:
                                self._slowlink_count = 1
                            self._last_slowlink_ts = now

                            # 动态降低码率（每次减少 20%）
                            self._bitrate = max(int(self._bitrate * 0.8), 300_000)  # 下限 300kbps
                            print(f"[slowLink] Lowering bitrate to {self._bitrate / 1_000_000:.2f} Mbps")

                            await self._plugin.send({
                                "body": {
                                    "request": "configure",
                                    "bitrate": self._bitrate,
                                    **self._media
                                }
                            })

                            # 若 slowlink 次数持续过高，尝试 ICE 重连
                            if self._slowlink_count >= 5:
                                if self._pc.iceConnectionState not in ("closed", "failed", "disconnected"):
                                    try:
                                        print("[slowLink] Too many slowlink reports, attempting ICE restart")
                                        await restart_ice(self._pc, self._plugin, self._media)
                                        self._slowlink_count = 0
                                    except Exception as e:
                                        print(f"[slowLink] ICE restart failed: {e}")
                else:
                    print(data)


async def publish(plugin, player, bitrate=10_000_000, min_bitrate=5_000_000):
    """
    Send video to the room.
    """
    pc = RTCPeerConnection()
    pcs.add(pc)

    @pc.on("iceconnectionstatechange")
    async def on_ice_state():
        print(f"[iceState] ICE connection state changed: {pc.iceConnectionState}")
        if pc.iceConnectionState in ["disconnected", "failed", "closed"]:
            try:
                await restart_ice(pc, plugin, media)
            except Exception as e:
                print(f"[iceRestart] Failed: {e}")

    @pc.on("connectionstatechange")
    async def on_connection_state():
        print(f"[webrtcState] WebRTC connection state is {pc.connectionState}")
        if pc.connectionState == "connected":
            print("[webrtcState] WebRTC PeerConnection is up")
        elif pc.connectionState == "closed":
            print("[webrtcState] PeerConnection closed, try ICE restart")
            # try:
            #     await restart_ice(pc, plugin, media)
            # except Exception as e:
            #     print(f"[iceRestart] Failed: {e}")

    # 设置 VP8 编码器静态比特率参数
    vpx.DEFAULT_BITRATE = bitrate
    vpx.MIN_BITRATE = min_bitrate
    vpx.MAX_BITRATE = bitrate
    vpx.PACKET_MAX = 1000

    # configure media
    media = {"audio": False, "video": True}
    if player and player.audio:
        pc.addTrack(player.audio)
        media["audio"] = True

    if player and player.video:
        # 添加视频轨道并获取发送器
        video_track = player.video
        video_sender = pc.addTrack(video_track)
    else:
        # 添加默认视频轨道
        video_track = VideoStreamTrack()
        video_sender = pc.addTrack(video_track)

    # 设置编码参数
    # try:
    #     codec = RTCRtpCodecParameters(
    #         mimeType="video/VP8", clockRate=90000, payloadType=100
    #     )
    #     rtcp = RTCRtcpParameters(cname="video")

    #     send_params = RTCRtpSendParameters(
    #         codecs=[codec],
    #         encodings=[{
    #             "maxBitrate": bitrate,
    #             "minBitrate": min_bitrate,
    #             "scaleResolutionDownBy": 1.0,
    #         }],
    #         rtcp=rtcp
    #     )

    #     await video_sender.send(send_params)
    #     print(f"Configured video sender: {bitrate / 1_000_000} Mbps")
    # except Exception as e:
    #     print(f"Failed to configure video sender: {e}")

    # send offer
    await pc.setLocalDescription(await pc.createOffer())
    request = {"request": "configure"}
    request.update(media)
    response = await plugin.send(
        {
            "body": request, 
            "jsep": {
                "sdp": pc.localDescription.sdp,
                "trickle": False,
                "type": pc.localDescription.type,
            },
        }
    )

    # apply answer
    await pc.setRemoteDescription(
        RTCSessionDescription(
            sdp=response["jsep"]["sdp"], type=response["jsep"]["type"]
        )
    )

    session._pc = pc
    session._plugin = plugin
    session._media = media
    session._bitrate = bitrate

async def restart_ice(pc, plugin, media):
    print("[iceRestart] Restarting ICE manually")

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    response = await plugin.send({
        "body": {"request": "configure", **media},
        "jsep": {
            "type": offer.type,
            "sdp": offer.sdp,
            "trickle": False
        }
    })

    await pc.setRemoteDescription(RTCSessionDescription(
        sdp=response["jsep"]["sdp"],
        type=response["jsep"]["type"]
    ))

    print("[iceRestart] ICE restart completed")


    await pc.setRemoteDescription(
        RTCSessionDescription(sdp=response["jsep"]["sdp"], type=response["jsep"]["type"])
    )
    print("[iceRestart] ICE restart successful")

async def subscribe(session, room, feed, recorder):
    pc = RTCPeerConnection()
    pcs.add(pc)

    @pc.on("track")
    async def on_track(track):
        print("Track %s received" % track.kind)
        if track.kind == "video":
            recorder.addTrack(track)
        if track.kind == "audio":
            recorder.addTrack(track)

    # subscribe
    plugin = await session.attach("janus.plugin.videoroom")
    response = await plugin.send(
        {"body": {"request": "join", "ptype": "subscriber", "room": room, "feed": feed}}
    )

    # apply offer
    await pc.setRemoteDescription(
        RTCSessionDescription(
            sdp=response["jsep"]["sdp"], type=response["jsep"]["type"]
        )
    )

    # send answer
    await pc.setLocalDescription(await pc.createAnswer())
    response = await plugin.send(
        {
            "body": {"request": "start"},
            "jsep": {
                "sdp": pc.localDescription.sdp,
                "trickle": False,
                "type": pc.localDescription.type,
            },
        }
    )
    await recorder.start()


async def run(player, recorder, room, session):
    await session.create()

    # join video room
    plugin = await session.attach("janus.plugin.videoroom")
    response = await plugin.send(
        {
            "body": {
                "display": "aiortc",
                "ptype": "publisher",
                "request": "join",
                "room": room,
            }
        }
    )
    publishers = response["plugindata"]["data"]["publishers"]
    for publisher in publishers:
        print("id: %(id)s, display: %(display)s" % publisher)

    # send video
    await publish(plugin=plugin, player=player)

    # receive video
    if recorder is not None and publishers:
        await subscribe(
            session=session, room=room, feed=publishers[0]["id"], recorder=recorder
        )

    # exchange media for 10 minutes
    print("Exchanging media")
    await asyncio.sleep(600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Janus")
    parser.add_argument("url", help="Janus root URL, e.g. http://localhost:8088/janus")
    parser.add_argument(
        "--room",
        type=int,
        default=1234,
        help="The video room ID to join (default: 1234).",
    )
    parser.add_argument("--play-from", help="Read the media from a file and sent it.")
    parser.add_argument("--record-to", help="Write received media to a file.")
    parser.add_argument(
        "--play-without-decoding",
        help=(
            "Read the media without decoding it (experimental). "
            "For now it only works with an MPEGTS container with only H.264 video."
        ),
        action="store_true",
    )
    parser.add_argument("--verbose", "-v", action="count")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # create signaling and peer connection
    session = JanusSession(args.url)

    # create media source
    if args.play_from:
        player = MediaPlayer(args.play_from, decode=not args.play_without_decoding, loop=True, options={"realtime": "1"})
    else:
        player = None

    # create media sink
    if args.record_to:
        recorder = MediaRecorder(args.record_to)
    else:
        recorder = None

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            run(player=player, recorder=recorder, room=args.room, session=session)
        )
    except KeyboardInterrupt:
        pass
    finally:
        if recorder is not None:
            loop.run_until_complete(recorder.stop())
        loop.run_until_complete(session.destroy())

        # close peer connections
        coros = [pc.close() for pc in pcs]
        loop.run_until_complete(asyncio.gather(*coros))
