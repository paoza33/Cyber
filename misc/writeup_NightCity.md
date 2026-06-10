# Writeup  Night City

**Catégorie :** Reverse Engineering / Crypto
**Difficulté :** Hard
**Plateforme :** Windows x64 (Unity IL2CPP)
**Flag :** `BS{n0_H4Ppy_ENd1nG_4_F0Lk5_L1kE_u5}`

---

## Énoncé

Night City, 2075. We captured an Arasaka executive and extracted his Neural Vault. The data inside is worth a fortune. Arasaka’s security is the best on the Net. One mistake and MaxTac will find us. But if we pull this off, we can leave Night City for good and finally live the life we’ve been dreaming of, Choom.

## Outils utilisés

- **Il2CppDumper** ou **Il2CppInspector** pour reconstruire les métadonnées managées depuis IL2CPP
- **dnSpy** ou **ILSpy** pour inspecter le DummyDll généré
- **AssetRipper** ou **UABE/UABEA** pour extraire les assets Unity
- **Python 3** avec `pycryptodome` ou `cryptography` pour rejouer le KDF et déchiffrer

## Étape 0 - Reconnaissance

`strings NeuralVault.exe` donne rien. Le `.exe` est une coquille IL2CPP qui quitte après quelques `Debug.Log` narratifs. `Player.log` dans `%LOCALAPPDATA%Low\Arasaka Corp\NeuralVault\` contient les 8 lignes d'un faux boot sequence, aucune info utile.

Le layout du build confirme IL2CPP :
- Pas de `Managed/Assembly-CSharp.dll` (Mono aurait laissé ça, j'ai pas été sympa pour le coup)
- Présence de `GameAssembly.dll` à la racine
- `NeuralVault_Data/il2cpp_data/Metadata/global-metadata.dat`

-> Il faut dumper le binaire natif avec Il2CppDumper.

## Étape 1  Dump IL2CPP

```
Il2CppDumper.exe GameAssembly.dll global-metadata.dat ./out
```

Sortie : `DummyDll/Assembly-CSharp.dll` qu'on ouvre dans dnSpy. On découvre (dans `NeuralVault.*`) :

```
Core:
  HumanClass (abstract)
  Netrunner, Techie, Fixer, Solo   (classes réelles)
  Corpo, Nomad                     (suspects  leurres)

Crypto:
  NeuralVault.Unlock()             <- entry point du vrai flag
  MasterKeyBuilder.Build()         <- KDF principal
  BiometricsExtractor.ExtractIV()  <- lit l'IV depuis une texture
  NeuralCrypto                     <- AES-256-CBC helper

Cyberware:
  CyberwareRegistrySO              <- ScriptableObject avec blobs XORés
  AugID (enum)

Fakes:
  PrintFlag.Emit()                 <- fausse piste XOR
  FlagCrypto.LegacyDecrypt()       <- fausse piste AES avec Corpo+Nomad

Utils:
  Blackwall_1448855.Decode/Encode  <- XOR obfuscator

Bootstrap / Arasaka_Defense        <- entry points de la scène
```

## Étape 2 - Identifier et écarter les leurres

**Leurre 1 - `PrintFlag.Emit()`** : un `byte[] _legacyBlob` XORé avec un pad en clair `ARASAKA_CORP_INTERNAL_KEY_DO_NOT_SHARE` :

```python
pad = b"ARASAKA_CORP_INTERNAL_KEY_DO_NOT_SHARE"
blob = bytes.fromhex("03013a1e001315...")  # extraire depuis dnSpy
print(bytes(b ^ pad[i % len(pad)] for i, b in enumerate(blob)))
# -> BS{MAXTAC_1s_c0M1nG}
```

Submission -> rejetée. **C'est un leurre.**

**Leurre 2  `FlagCrypto.LegacyDecrypt()`** : chaîne plus crédible. AES-256-CBC, IV = `00 11 22 ... FF`, clé = `SHA256(Corpo.GetNeuralSignature() || Nomad.GetNeuralSignature())`. En rejouant les signatures (SHA256 de `name || salt` où les salts sont visibles dans chaque classe), on obtient `BS{1t_w4s_4n_4rasaka_tr4p}`. Submission -> rejetée. **Deuxième leurre, plus vicieux parce qu'il justifie la présence de `Corpo` et `Nomad` comme classes "legacy".** (désolé)

Les deux leurres ne sont jamais appelés depuis le runtime (pas de référence dans `Bootstrap` ou `Start`). **Red flag** : le vrai flag est dans une méthode jamais exécutée non plus, `NeuralVault.Unlock()`.

## Étape 3  Analyse de `NeuralVault.Unlock()`

```csharp
public static string Unlock()
{
    byte[] key = MasterKeyBuilder.Build();
    byte[] iv = BiometricsExtractor.ExtractIV();
    byte[] plain = NeuralCrypto.DecryptAesCbc(Ciphertext, key, iv);
    return Encoding.UTF8.GetString(plain);
}
```

Le `Ciphertext` est un `byte[]` de 48 bytes visible en clair dans dnSpy. Reste à reconstituer la clé AES-256 (32 bytes) et l'IV (16 bytes).

## Étape 4  Extraire l'IV (stéganographie)

`BiometricsExtractor.ExtractIV()` lit `Resources.Load<Texture2D>("arasaka_portrait")` et récupère le canal bleu (`b`) des 16 premiers pixels.

Extraction de la texture depuis `NeuralVault_Data/resources.assets` avec AssetRipper ou UABE -> on récupère `arasaka_portrait.png` (64×64 RGBA). En Python :

```python
from PIL import Image
img = Image.open("arasaka_portrait.png").convert("RGBA")
pixels = list(img.getdata())
iv = bytes(p[2] for p in pixels[:16])   # canal B des 16 premiers pixels
print(iv.hex())
```

**IV obtenu** (16 bytes).

## Étape 5  Extraire le registry binaire

`MasterKeyBuilder.Build()` charge `Resources.Load<CyberwareRegistrySO>("cyberware_registry")`. Ce ScriptableObject contient :
- `EncodedClassBlobs` liste de `byte[]` XORés (4 entrées)
- `AugSequence` liste d'`AugID` (6 entrées)
- `RotationSeed` un byte (`0x5A`)

Extraction avec **UABE** : ouvrir `resources.assets`, trouver le MonoBehaviour `cyberware_registry`, exporter en JSON ou lire les bytes directement. Le fichier ne contient **aucune string** lisible seulement les blobs XORés et les enum values.

## Étape 6  Décoder les blobs XOR (`Blackwall_1448855`)

Le décodeur dans `Blackwall_1448855.Decode` :

```csharp
private const byte XorKey = 0x7C;

public static string Decode(byte[] encoded)
{
    byte[] buf = new byte[encoded.Length];
    for (int i = 0; i < encoded.Length; i++)
        buf[i] = (byte)(encoded[i] ^ (XorKey + (byte)(i & 0x0F)));
    return Encoding.UTF8.GetString(buf);
}
```

Appliqué aux 4 blobs du registry -> `["Techie", "Netrunner", "Fixer", "Solo"]` (ordre critique, c'est la séquence d'instanciation).

## Étape 7  Reproduire `GetNeuralSignature()` pour chaque classe

Dans chaque classe dérivée, `InternalSalt` est un `byte[16]` hardcodé. La signature est :

```python
import hashlib
def signature(name: str, salt: bytes) -> bytes:
    return hashlib.sha256(name.encode() + salt).digest()
```

Les salts sont visibles dans dnSpy. On concatène les 4 signatures dans l'ordre du registry : `sig(Techie) || sig(Netrunner) || sig(Fixer) || sig(Solo)` -> 128 bytes.

## Étape 8  Reproduire `ApplyAugPermutation`

```python
def apply_aug_permutation(blob: bytes, augs: list[int], seed: int) -> bytes:
    out = bytearray(blob)
    state = seed
    for r, aug in enumerate(augs):
        state = ((state + aug) ^ r) & 0xFF
        for i in range(len(out)):
            out[i] ^= state
            state = ((state << 1) | (state >> 7)) & 0xFF
    return bytes(out)
```

Appliqué au blob de 128 bytes avec `augs = [CerebralBooster, Sandevistan, MonowireWhip, Kiroshi, SyntheticMuscles, OpticalCamo]` (valeurs byte 0x88, 0x11, 0x66, 0x22, 0x77, 0xAA) et `seed = 0x5A`.

## Étape 9  Reproduire `FinalKdf` (la partie retorse)

C'est là où l'écart se creuse entre ceux qui lisent vraiment le code et ceux qui scriptent de travers. Le KDF a 4 phases :

**Phase 1  Dérivation de 4 sous-clés taguées :**

```python
def derive_subkey(inp: bytes, tag: int) -> bytes:
    return hashlib.sha256(inp + bytes([tag])).digest()

k0 = derive_subkey(input_blob, 0xA1)
k1 = derive_subkey(input_blob, 0xB2)
k2 = derive_subkey(input_blob, 0xC3)
k3 = derive_subkey(input_blob, 0xD4)
```

**Phase 2  Construction de la S-box via Fisher-Yates seeded :**

```python
def build_sbox(augs: list[int]) -> list[int]:
    sbox = list(range(256))
    keystream = hashlib.sha256(bytes(augs)).digest()
    ks_idx = 0
    for i in range(255, 0, -1):
        j = keystream[ks_idx % 32] % (i + 1)
        ks_idx += 1
        sbox[i], sbox[j] = sbox[j], sbox[i]
        if ks_idx == 32:
            keystream = hashlib.sha256(keystream).digest()
            ks_idx = 0
    return sbox
```

Piège potentiel : le re-hash de `keystream` toutes les 32 itérations, facile à rater.

**Phase 3  Nombre de rounds dérivé :**

```python
rounds = 12 + (sum(augs) % 5)   # 12 à 16 rounds
```

Piège : beaucoup de reversers écriraient `len(augs)` ou un literal `16`. Le code utilise explicitement la somme modulo 5.

**Phase 4  Boucle Feistel-like :**

```python
left  = bytearray(k0[:16])
right = bytearray(k1[:16])
chainKey = bytearray(k2[:16] + k3[:16])

for r in range(rounds):
    tweak = bytes(chainKey) + bytes([r]) + iv
    f = hashlib.sha256(tweak).digest()
    new_right = bytearray(16)
    for i in range(16):
        mixed = (f[i] ^ right[i]) & 0xFF
        new_right[i] = (left[i] ^ sbox[mixed]) & 0xFF
    left = right[:]
    right = new_right
    # Update partiel de chainKey  le piège
    offset = (r * 5) % 16
    for i in range(16):
        chainKey[(offset + i) % 32] = f[16 + i]   # à vérifier contre le code original

final_key = bytes(left) + bytes(right)
```

Piège subtil : l'update de `chainKey` à un offset `(r * 5) % 16` avec un wrap-around. Si on code `(r * 5)` sans `% 16`, on déborde et la clé diverge. C'est le type de détail qui prend 30 minutes à debug si on rate.

## Étape 10  Déchiffrer

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

cipher = Cipher(algorithms.AES(final_key), modes.CBC(iv))
decryptor = cipher.decryptor()
padded = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = PKCS7(128).unpadder()
plaintext = unpadder.update(padded) + unpadder.finalize()

print(plaintext.decode())
# -> BS{n0_H4Ppy_ENd1nG_4_F0Lk5_L1kE_u5}
```

## Récap de la solution

| Étape | Action | Outil |
|-------|--------|-------|
| 1 | Dump IL2CPP | Il2CppDumper |
| 2 | Inspection du code managé | dnSpy |
| 3 | Identifier les 2 leurres, retenir `NeuralVault.Unlock` | analyse statique |
| 4 | Extraire `arasaka_portrait.png` et lire le canal bleu des 16 premiers pixels -> IV | AssetRipper + Python |
| 5 | Extraire `cyberware_registry.asset` -> blobs XORés + augs + seed | UABE |
| 6 | Décoder les blobs via XOR `0x7C + (i & 0x0F)` -> ordre des classes | Python |
| 7 | Reproduire les signatures SHA256 de chaque classe | Python |
| 8 | Appliquer la permutation par augs avec rotation seed | Python |
| 9 | Reproduire le KDF multi-round (S-box Fisher-Yates, Feistel, chainKey offset) | Python |
| 10 | AES-256-CBC decrypt -> flag | Python |

## Pièges classiques

- **Tomber sur `PrintFlag`** : le pad XOR est trop évident, le flag qui sort (`BS{MAXTAC_1s_c0M1nG}`) a même l'air plausible.
- **Tomber sur `FlagCrypto`** : chaîne AES complète, leurre crédible. `BS{1t_w4s_4n_4rasaka_tr4p}` sort clean.
- **Ignorer `Corpo`/`Nomad`** dans les classes disponibles : elles servent **uniquement** au leurre #2. Leur présence ne signifie pas qu'elles font partie du vrai KDF.
- **Ne pas extraire le ScriptableObject binaire** : il est indispensable pour obtenir l'ordre des classes et les augs. Sans UABE/AssetRipper, le challenge est bloqué.
- **Rater le re-hash de `keystream`** dans la S-box, ou l'offset modulaire de `chainKey` : les deux font diverger la clé finale silencieusement.
- **Confondre `Bootstrap` et `Arasaka_Defense`** : deux classes apparentes, aucune ne touche à la crypto. Le Arasaka_Defense n'a pour seul rôle que d'afficher les logs narratifs.

## Concepts testés

- Reverse engineering IL2CPP (flux : natif C++ -> metadata -> DummyDll)
- Extraction d'assets Unity binaires (ScriptableObject, Texture2D)
- Identification et rejet de red herrings
- Stéganographie LSB / canal de couleur
- Reconstruction d'un KDF custom en dehors du binaire
- Reimplémentation d'une chaîne crypto avec plusieurs primitives (SHA-256, AES-CBC, Fisher-Yates, Feistel)

## Flag final

```
BS{n0_H4Ppy_ENd1nG_4_F0Lk5_L1kE_u5}
```
