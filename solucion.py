from scapy.all import rdpcap, Raw
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Cargar la llave privada RSA
with open("clave_privada.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

# 2. Leer el archivo PCAP
packets = rdpcap("transacciones_cifradas.pcap")

pin = None
salt = None
aes_key = None

# 3. Buscar el paquete RSA_PIN
for pkt in packets:
    if pkt.haslayer(Raw):
        data = pkt[Raw].load
        if b"RSA_PIN" in data:
            # El cifrado RSA de 2048 bits pesa exactamente 256 bytes.
            ciphertext = data[-256:]
            # La salt de 16 bytes está justo antes
            salt = data[-256-16:-256]
            
            try:
                pin_bytes = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                pin = int(pin_bytes.decode('utf-8'))
                print(f"[+] PIN recuperado mediante RSA")
                print(f"[+] PIN: {pin}")
                break
            except Exception as e:
                print(f"Error al descifrar PIN: {e}")

# 4. Derivar la clave AES con Scrypt
if pin is not None and salt is not None:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    aes_key = kdf.derive(str(pin).encode('utf-8'))
    print(f"[+] Clave AES derivada correctamente")

# 5. Descifrar las transacciones AES-GCM
if aes_key is not None:
    aesgcm = AESGCM(aes_key)
    transactions_found = 0
    print("\n========= TRANSACCIONES =========")
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            
            # Ignorar el paquete del PIN
            if b"RSA_PIN" in data:
                continue
            
            # Solo intentar con paquetes que tengan un tamaño mínimo
            if len(data) > 30:
                # Probar a descifrar asumiendo diferentes offsets (por si hay cabecera)
                descifrado = False
                for offset in range(0, 20):
                    try:
                        # Intentamos extraer nonce (12 bytes) desde el offset
                        nonce = data[offset:offset+12]
                        ciphertext = data[offset+12:]
                        
                        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                        
                        # Si llega aquí, el descifrado fue exitoso
                        transactions_found += 1
                        print(f"\n[Transacción {transactions_found}]")
                        print(plaintext.decode('utf-8'))
                        descifrado = True
                        break # Salir del bucle de offsets
                    except Exception:
                        continue # Probar con el siguiente offset
                
                # Si no se pudo descifrar con ningún offset, ignorar el paquete
                if not descifrado:
                    continue
                    
    print(f"\n[+] Transacciones cifradas encontradas: {transactions_found}")