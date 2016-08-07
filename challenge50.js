function stringToArrayBuffer(s) {
	const len = s.length;
	const buf = new ArrayBuffer(len);
	const view = new Uint8Array(buf);

	for (let i = 0; i < len; ++i) {
		view[i] = s.charCodeAt(i);
	}

	return buf;
}

function arrayBufferToString(buf) {
	return String.fromCharCode.apply(null, new Uint8Array(buf));
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
		}).then(ciphertext => ciphertext.slice(-blockSize));
}

fetch('https://raw.githubusercontent.com/Metalnem/cryptopals-go/master/challenge50.dat')
	.then(response => response.arrayBuffer())
	.then(buf => {
		const key = stringToArrayBuffer('YELLOW SUBMARINE');
		const expectedHash = '296b8d7cb78a243dda4d0a61d33bbdd1';

		return cbcMacHash(buf, key).then(actualHash => {
			if (arrayBufferToHex(actualHash) === expectedHash) {
				const script = document.createElement('script');
				script.innerHTML = arrayBufferToString(buf);
				document.head.appendChild(script);
			}
		});
	});
