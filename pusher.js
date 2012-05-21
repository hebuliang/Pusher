/**
 * WebSocket服务器程序
 * Surpport [RFC 6455] only
 */
var util = require("util"), 
	net = require("net"), 
	http = require("http"), 
	crypto = require('crypto'), 
	buffer = require('buffer'), 
	PORT = 8888, 
	CRLF = '\r\n', 
	MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function createServer() {
	return new Pusher();
};

function Pusher() {
	var server = this, clients = [];
	http.Server.call(server);

	server.addListener("connection", function(socket) {
		// save all clients when connected;
		clients.push(socket);
	});

	server.addListener("request", function(req, res) {
		res.writeHead(200, {
			"Content-Type" : "text/plain"
		});
		res.write("okay");
		res.end();
	});
	/**
	 * Client handshake listener
	 */
	server.addListener("upgrade", function(req, socket, upgradeHead) {
		var key = req.headers['sec-websocket-key'];
		var shasum = crypto.createHash('sha1');
		key = shasum.update(key + MAGIC);
		key = shasum.digest('base64');

		var respHeaders = ['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Connection: Upgrade', 'Sec-WebSocket-Accept: ' + key];

		// 响应头最后要以2个CRLF结尾[RFC6455]
		socket.write(respHeaders.concat('', '').join(CRLF));

		/**
		 *  服务器端解析客户端数据
		 *  WebSocket Frame格式
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 +-+-+-+-+-------+-+-------------+-------------------------------+
		 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
		 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
		 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
		 | |1|2|3|       |K|             |                               |
		 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
		 |     Extended payload length continued, if payload len == 127  |
		 + - - - - - - - - - - - - - - - +-------------------------------+
		 |                               |Masking-key, if MASK set to 1  |
		 +-------------------------------+-------------------------------+
		 | Masking-key (continued)       |          Payload Data         |
		 +-------------------------------- - - - - - - - - - - - - - - - +
		 :                     Payload Data continued ...                :
		 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
		 |                     Payload Data continued ...                |
		 +---------------------------------------------------------------+
		 */
		socket.ondata = function(frame, start, end) {
			/*
			 * 包首16bit(2byte)
			 *
			 * first byte解释如下:
			 * FIN + RSV1 + RSV2 + RSV3:0000连续数据  1000分片数据
			 * opcode: 0000 表示连续消息分片
			 0001表示文本消息分片
			 0010表未二进制消息分片
			 1000表示客户端发起的连接关闭
			 1001表示心跳ping
			 1010表示心跳pong
			 * --------------------------------------------
			 * second byte解释如下:
			 * 掩码位1bit 1加密  0未加密 (客户端发送的数据必须加密  [RFC6455])
			 *
			 * 剩下7bit需要计算:
			 * 如果该值介于0000 0000 和 0111 1101(0~125)之间,那么该值就代表了实际数据的长度;
			 * 如果该值等于0111 1110(126),那么接下来的2个字节代表数据长度;
			 * 如果该值等于0111 1111(127),那么接下来的8个字节代表数据长度.
			 */

			var firstByte = frame[start], secondByte = frame[start + 1], FIN = Boolean(firstByte & 0x80), RSV1 = Boolean(firstByte & 0x40), RSV2 = Boolean(firstByte & 0x20), RSV3 = Boolean(firstByte & 0x10), MASK = Boolean(secondByte & 0x80), OPCODE = firstByte & 0x0F, payloadLen = secondByte & 0x7F,
			// 真实数据长度
			appDataLen;

			// 检测socket连接关闭
			// Control Frame分片检查(不允许分片)
			if(OPCODE == 0x8) {
				console.log('socket closed');
				socket.end();
			} else if(OPCODE > 0x8) {
				if(!FIN || payloadLen > 125) {
					console.log('Control frames must not be fragmented');
					socket.end();
				}
			}

			// 获取数据
			var payloadLenBuf, masksBuf = new Buffer(4), dataStartIdx, dataBuf, getDataLen = function(buf) {
				var len = 0;
				for(var i = 0; i < buf.length; i++) {
					len += parseInt(buf[i]);
				}
				return len;
			};
			if(payloadLen == 126) {
				// 数据长度buffer
				payloadLenBuf = new buffer(2);
				frame.copy(payloadLenBuf, 0, start + 2, start + 4);
				appDataLen = getDataLen(payloadLenBuf);

				// 加密掩码buffer
				frame.copy(masksBuf, 0, start + 4, start + 8);

				// 数据起始索引
				dataStartIdx = start + 8;

			} else if(payloadLen == 127) {
				payloadLenBuf = new buffer(8);
				frame.copy(payloadLenBuf, 0, start + 2, start + 10);
				appDataLen = getDataLen(payloadLenBuf);

				frame.copy(masksBuf, 0, start + 10, start + 14);
				dataStartIdx = start + 14;
			} else {
				frame.copy(masksBuf, 0, start + 2, start + 6);
				dataStartIdx = start + 6;
				appDataLen = payloadLen;
			}
			// 取得加密数据
			dataBuf = frame.slice(dataStartIdx, dataStartIdx + appDataLen);

			// 还原数据
			var temp = [];
			for(var i = 0; i < dataBuf.length; i++) {
				temp.push(String.fromCharCode(dataBuf[i] ^ masksBuf[i % 4]));
			}
			var data = temp.join('');

			// 向客户端发送数据
			function send(socket, data) {
				var frames, len = new Buffer(data, 'utf-8').length;
				if(data.length > 125) {
					frames = new Buffer(4);
					frames[0] = 0x81;
					frames[1] = 0x7e;
					frames[2] = length >> 8;
					frames[3] = length & 0xFF;
					// 1111 1111
				} else {
					frames = new Buffer(2);
					frames[0] = 0x81;
					frames[1] = len;
				}

				if(!!socket.writable) {
					socket.write(frames, 'binary');
					socket.write(data, 'utf-8');
				}
			}

			// 广播数据
			function broadcast(data) {
				if(clients.length > 0) {
					clients.forEach(function(client) {
						send(client, data);
					});
				}
			}

			// send data to client
			broadcast(data);
		};
	});
};

/**
 * 继承http.Server
 * 监听 request|connection|upgrade 事件
 */
util.inherits(Pusher, http.Server);

var server = createServer();
server.listen(PORT, function() {
	console.log('server started at port 8888...');
});
