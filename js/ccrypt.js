var init=0;

async function doenc() {
	const msg=document.getElementById('msg').value;
	const out=document.getElementById('out');
	try {
		res=await encryptAES( msg );
	}
	catch( err ) {
		alert("Encryption failed!");
		console.log(err);
		return;
	}
	out.innerHTML="res: "+res;
}

async function dodec() {
  const enc=document.getElementById('enc').value;
  const out=document.getElementById('out');
  try {
	  res=await decryptAES( enc );
	} catch( err ) {
		alert("Decryption failed!");
		console.log(err);
		return;
	}
  out.innerHTML="msg: "+res;
}

async function encryptAES( plaintext ) {
  var iv = crypto.getRandomValues(new Uint8Array(16));
  const alg = { name: 'AES-CBC', iv: iv };
	const pw=document.getElementById('key').value;
	const pwUtf8 = new TextEncoder().encode(pw);
	const	pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);
  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']);
  const ptUint8 = new TextEncoder().encode(plaintext);
  const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8);
  const ctArray = Array.from(new Uint8Array(ctBuffer));
	const ctivArray=Array.from(iv).concat(ctArray);
  const ctStr = ctivArray.map(byte => String.fromCharCode(byte)).join('');
  return btoa(ctStr);
}

async function decryptAES( ciphertext ) {
	const ctivStr=atob(ciphertext);
	const ctivUint8=new Uint8Array(ctivStr.match(/[\s\S]/g).map(ch => ch.charCodeAt(0)));
  const iv = ctivUint8.slice(0,16);
  const alg = { name: 'AES-CBC', iv: iv };
	const pw=document.getElementById('key').value;
	const pwUtf8 = new TextEncoder().encode(pw);
	const	pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);
  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']);
  const ctUint8 = ctivUint8.slice(16,);
  const plainBuffer = await crypto.subtle.decrypt(alg, key, ctUint8);
  const plaintext = new TextDecoder().decode(plainBuffer);
  return plaintext;
}
