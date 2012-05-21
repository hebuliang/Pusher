/**
 * WebSocket����������
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

		// ��Ӧͷ���Ҫ��2��CRLF��β[RFC6455]
		socket.write(respHeaders.concat('', '').join(CRLF));

		/**
		 *  �������˽����ͻ�������
		 *  WebSocket Frame��ʽ
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
			 * ����16bit(2byte)
			 *
			 * first byte��������:
			 * FIN + RSV1 + RSV2 + RSV3:0000��������  1000��Ƭ����
			 * opcode: 0000 ��ʾ������Ϣ��Ƭ
			 0001��ʾ�ı���Ϣ��Ƭ
			 0010��δ��������Ϣ��Ƭ
			 1000��ʾ�ͻ��˷�������ӹر�
			 1001��ʾ����ping
			 1010��ʾ����pong
			 * --------------------------------------------
			 * second byte��������:
			 * ����λ1bit 1����  0δ���� (�ͻ��˷��͵����ݱ������  [RFC6455])
			 *
			 * ʣ��7bit��Ҫ����:
			 * �����ֵ����0000 0000 �� 0111 1101(0~125)֮��,��ô��ֵ�ʹ�����ʵ�����ݵĳ���;
			 * �����ֵ����0111 1110(126),��ô��������2���ֽڴ������ݳ���;
			 * �����ֵ����0111 1111(127),��ô��������8���ֽڴ������ݳ���.
			 */

			var firstByte = frame[start], secondByte = frame[start + 1], FIN = Boolean(firstByte & 0x80), RSV1 = Boolean(firstByte & 0x40), RSV2 = Boolean(firstByte & 0x20), RSV3 = Boolean(firstByte & 0x10), MASK = Boolean(secondByte & 0x80), OPCODE = firstByte & 0x0F, payloadLen = secondByte & 0x7F,
			// ��ʵ���ݳ���
			appDataLen;

			// ���socket���ӹر�
			// Control Frame��Ƭ���(�������Ƭ)
			if(OPCODE == 0x8) {
				console.log('socket closed');
				socket.end();
			} else if(OPCODE > 0x8) {
				if(!FIN || payloadLen > 125) {
					console.log('Control frames must not be fragmented');
					socket.end();
				}
			}

			// ��ȡ����
			var payloadLenBuf, masksBuf = new Buffer(4), dataStartIdx, dataBuf, getDataLen = function(buf) {
				var len = 0;
				for(var i = 0; i < buf.length; i++) {
					len += parseInt(buf[i]);
				}
				return len;
			};
			if(payloadLen == 126) {
				// ���ݳ���buffer
				payloadLenBuf = new buffer(2);
				frame.copy(payloadLenBuf, 0, start + 2, start + 4);
				appDataLen = getDataLen(payloadLenBuf);

				// ��������buffer
				frame.copy(masksBuf, 0, start + 4, start + 8);

				// ������ʼ����
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
			// ȡ�ü�������
			dataBuf = frame.slice(dataStartIdx, dataStartIdx + appDataLen);

			// ��ԭ����
			var temp = [];
			for(var i = 0; i < dataBuf.length; i++) {
				temp.push(String.fromCharCode(dataBuf[i] ^ masksBuf[i % 4]));
			}
			var data = temp.join('');

			// ��ͻ��˷�������
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

			// �㲥����
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
 * �̳�http.Server
 * ���� request|connection|upgrade �¼�
 */
util.inherits(Pusher, http.Server);

var server = createServer();
server.listen(PORT, function() {
	console.log('server started at port 8888...');
});
