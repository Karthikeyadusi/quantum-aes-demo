let key = '';
let iv = '';

// -------- Generate QRNG Key --------
async function generateQRNG() {

// After (your Render URL)
const res = await fetch('https://quantum-aes-demo.onrender.com/generate_qrng');
    const data = await res.json();
    key = data.key;
    iv = data.iv;
}

// -------- Text Encryption --------
async function encryptText() {
    if (!key) await generateQRNG();
    const text = document.getElementById('textInput').value.trim();
    if (!text) return alert("Enter some text to encrypt!");

    const res = await ('https://quantum-aes-demo.onrender.com/encrypt_text',{
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({text, key, iv})
    });
    const data = await res.json();

    const encSpan = document.getElementById('encText');
    encSpan.innerText = data.encrypted;

    // Show copy icon
    document.getElementById('copyEncBtn').style.display = 'inline-block';
}

// -------- Text Decryption --------
async function decryptText() {
    const enc = document.getElementById('decInput').value.trim();
    if (!enc) return alert("Paste the encrypted text to decrypt!");

    const res = await fetch('https://quantum-aes-demo.onrender.com/decrypt_text', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({encrypted: enc, key, iv})
    });
    const data = await res.json();
    document.getElementById('decText').innerText = data.decrypted;
}
// -------- Hybrid Image Encryption --------
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('encryptImgBtn').addEventListener('click', encryptImage);
});
async function encryptImage() {
    if (!key) await generateQRNG();

    const fileInput = document.getElementById('imageInput');
    const file = fileInput.files[0];
    if (!file) return alert("Select an image!");

    // Generate random AES key & IV for this image
    const imageKey = crypto.getRandomValues(new Uint8Array(16));
    const ivForImage = crypto.getRandomValues(new Uint8Array(16));

    // Read image as ArrayBuffer
    const arrayBuffer = await file.arrayBuffer();

    // Encrypt image using SubtleCrypto AES-CBC
    const cryptoKey = await crypto.subtle.importKey(
        "raw", imageKey, {name: "AES-CBC"}, false, ["encrypt"]
    );
    const encryptedBuffer = await crypto.subtle.encrypt(
        {name: "AES-CBC", iv: ivForImage},
        cryptoKey,
        arrayBuffer
    );

    // Prepend IV and convert to base64 for memory storage
    const combined = new Uint8Array(ivForImage.length + encryptedBuffer.byteLength);
    combined.set(ivForImage, 0);
    combined.set(new Uint8Array(encryptedBuffer), ivForImage.length);
    const base64EncryptedImage = btoa(String.fromCharCode(...combined));

    // Store base64 in element dataset for later
    const encPreview = document.getElementById('encImgPreview');
    encPreview.dataset.encryptedImage = base64EncryptedImage;

    // Encrypt AES key using backend
    const res = await fetch('https://quantum-aes-demo.onrender.com/encrypt_text', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ text: Array.from(imageKey), key, iv })
    });
    const data = await res.json();

    // Show encrypted key in preview
    encPreview.innerText = data.encrypted;
    encPreview.dataset.full = data.encrypted;
    document.getElementById('copyEncImg').style.display = 'inline-block';

    alert("Image encrypted! Copy the key for decryption and save the encrypted image.");
}


// -------- Hybrid Image Decryption (Text-style flow) --------
async function decryptImage() {
    const encKey = document.getElementById('decImgInput').value.trim();
    if (!encKey) return alert("Paste the encrypted key to decrypt!");

    // 1️⃣ Decrypt AES key using main QRNG key
    const resKey = await fetch('https://quantum-aes-demo.onrender.com/decrypt_text', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({encrypted: encKey, key, iv})
    });
    const dataKey = await resKey.json();
    const imageKeyBytes = new Uint8Array(dataKey.decrypted);

    // 2️⃣ Get encrypted image from dataset
    const encPreview = document.getElementById('encImgPreview');
    const base64EncryptedImage = encPreview.dataset.encryptedImage;
    if (!base64EncryptedImage) return alert("No encrypted image found! Encrypt first.");

    const combined = Uint8Array.from(atob(base64EncryptedImage), c => c.charCodeAt(0));

    // 3️⃣ Separate IV and encrypted data
    const ivForImage = combined.slice(0,16);
    const encryptedData = combined.slice(16);

    // 4️⃣ Decrypt
    const cryptoKey = await crypto.subtle.importKey(
        "raw", imageKeyBytes, {name:"AES-CBC"}, false, ["decrypt"]
    );
    const decryptedBuffer = await crypto.subtle.decrypt(
        {name:"AES-CBC", iv:ivForImage},
        cryptoKey,
        encryptedData
    );

    // 5️⃣ Download decrypted image
    const blob = new Blob([decryptedBuffer], {type: 'image/png'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'decrypted_image.png';
    a.click();

    alert("Image decrypted and downloaded!");
}

// -------- Copy Functions --------
function copyText() {
    const encText = document.getElementById('encText').innerText;
    if(!encText) return alert('No text to copy!');
    navigator.clipboard.writeText(encText)
        .then(() => alert('Encrypted text copied!'))
        .catch(err => console.error('Failed to copy text:', err));
}

function copyImageEncrypted() {
    const encPreview = document.getElementById('encImgPreview');
    const fullEncrypted = encPreview.dataset.full;
    if(!fullEncrypted) return alert("No encrypted image key to copy!");
    navigator.clipboard.writeText(fullEncrypted)
        .then(() => alert("Encrypted image key copied!"))
        .catch(err => console.error("Failed to copy image key:", err));
}

// -------- Attach Copy Listeners --------
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('copyEncBtn').addEventListener('click', copyText);
    document.getElementById('copyEncImg').addEventListener('click', copyImageEncrypted);
});
