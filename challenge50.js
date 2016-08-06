function stringToArrayBuffer(s) {
	let len = s.length;
	let buf = new ArrayBuffer(len);
	let view = new Uint8Array(buf);

	for (let i = 0; i < len; ++i) {
		view[i] = s.charCodeAt(i);
	}

	return buf;
}

function arrayBufferToHex(buf) {
	let s = '';
	const view = new Uint8Array(buf);

	for (let c of view) {
		const hex = c.toString(16);
		s += hex.length === 1 ? '0' + hex : hex;
	}

	return s;
}

function cbcMacHash(data, key) {
	const subtle = window.crypto.subtle;
	const algorithm = 'AES-CBC';
	const blockSize = 16;

	const options = {
		name: algorithm
	};

	return subtle.importKey('raw', key, options, false, ['encrypt'])
		.then(function (key) {
			const iv = new Uint8Array(blockSize);

			const options = {
				name: algorithm,
				iv: iv
			};

			return subtle.encrypt(options, key, data);
		}).then(ciphertext => arrayBufferToHex(ciphertext.slice(-blockSize)));
}

let data = stringToArrayBuffer('alert(\'MZA who was that?\');\n');
let key = stringToArrayBuffer('YELLOW SUBMARINE');
let expectedHash = '296b8d7cb78a243dda4d0a61d33bbdd1';

cbcMacHash(data, key).then(actualHash => alert(actualHash === expectedHash));
