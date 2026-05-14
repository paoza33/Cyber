# Writeup - Indiana John

**Catégorie :** Stéganographie/OSINT
**Difficulté :** Medium

---

## Énoncé

> John hasn’t given any news for several months, but recently I received this photo of a man.

> Who is he? He doesn’t look like him, this is hiding something.

Fichiers fournis au joueur :

- `mysterious_man.png` - photo d'un homme inconnu
- `note.txt` - un message indiquant que le mot-clé est lié aux travaux de cet homme

---

## Étape 1 - Identifier l'homme et extraire le conteneur

### OSINT

Une recherche par image inversée (Google Lens, TinEye, Yandex Images) sur
`mysterious_man.png` identifie le personnage comme **Jürgen Spanuth**
(1907–1998), pasteur et chercheur allemand.

Spanuth est connu pour ses travaux hypothétiques sur la localisation de
l'**Atlantide**, qu'il situait en mer du Nord autour d'Helgoland. Ses ouvrages
de référence :

- *Das enträtselte Atlantis* (1953)
- *Atlantis of the North* (1979)

L'indice de la note pointe donc vers le thème **Atlantis** combiné au nom du
chercheur.

### Détection d'un fichier caché

```bash
binwalk mysterious_man.png
```

`binwalk` remonte une signature **ZIP** concaténée à la fin du PNG (après le
marqueur `IEND`). Extraction :

```bash
binwalk -e mysterious_man.png
```

Un fichier `.zip` se trouve dans `_mysterious_man.png.extracted/`.

### Déchiffrement du ZIP

Le ZIP est chiffré en AES.

`unzip` (InfoZIP) ne supporte pas AES. Il faut utiliser `7z` :

```bash
7z x XXXX.zip
# password demandé : Atlantis_Jurgen_Spanuth
```

Deux fichiers en sortent :

- `polluted.png` - image visiblement altérée
- `notes2.txt` - message d'étape

---

## Étape 2 - Retirer le poison du flux

### Analyse de la note

> I am on one of the Atlanteans’ migration routes. I’ve found Germanic swords here, along with a strange artifact. I've left you a map of my localisation.
> Based on my analysis, it should help me reach Atlantis. I can feel that I’m close.
> But I feel weakened; the wound I sustained while retrieving the artifact must be the cause. 
> I need to recover first.
> John


L'indice pointe vers une pollution répétée injectée dans le contenu binaire (le « flux ») du fichier.

### Identifier la pollution

```bash
file polluted.png
strings polluted.png | sort | uniq -c | sort -rn | head
```

La chaîne `pooooison` (et des fragments) apparaît de manière anormalement
fréquente. En hexadécimal :

```
70 6f 6f 6f 6f 69 73 6f 6e   →   706f6f6f6f69736f6e
```

### Premier nettoyage - le PNG

```bash
xxd -p polluted.png \
  | tr -d '\n' \
  | sed 's/706f6f6f6f69736f6e//g' \
  | xxd -r -p > decode.png
```

Le PNG nettoyé contient un gzip caché à l'intérieur :

```bash
binwalk -e decode.png
```

### Deuxième nettoyage - le gzip

Le `.gz` extrait est lui aussi pollué (la même séquence avait été injectée
dans les deux couches avant empaquetage). On répète :

```bash
xxd -p _decode.png.extracted/XXXX.gz \
  | tr -d '\n' \
  | sed 's/706f6f6f6f69736f6e//g' \
  | xxd -r -p > decode.tar.gz
tar -zxvf decode.tar.gz
```

Sortie :

- `localisation` - modèle 3D au format Wavefront
- `notes.txt` - message final

---

## Étape 3 - Lire le modèle 3D

### Note finale

> I found it. They said Atlantis was located either in Santorini or Crete, but that’s not true. Atlantis is real, but what I saw… it was beyond time. No one must find it. Delete all the research we’ve done. I’ll contact you again later. John

### Ouvrir le fichier

Le format `.obj` s'ouvre directement, sans conversion, dans n'importe quel
viewer 3D :

- **[Online 3D Viewer](https://3dviewer.net)** -> navigateur, zéro install, mais nécessite de renommer le fichier en .obj
- **Blender** -> local, complet, mais lourd
- **MeshLab** -> léger et performant

### Retrouver le flag

À l'ouverture, la scène contient de très nombreux cubes dispersés, dont
plusieurs amas qui forment ce qui ressemble à du texte selon l'angle de vue.
Une seule étape pour lire le vrai flag :

1. **Chercher ...** (Bonne chance).


### Flag

```
BS{1t_mUsT_r3M41n_h1Dd3n}
```

---

## Récapitulatif

| Étape | Technique | Outils |
|-------|-----------|--------|
| 1 - OSINT | Recherche par image inversée | Google Lens, TinEye, Yandex |
| 1 - Extraction | Données concaténées après `IEND` | `binwalk -e` |
| 1 - Déchiffrement | ZIP AES-256 | `7z x` |
| 2 - Détection pollution | Répétition anormale dans le binaire | `strings`, `file`, `xxd` |
| 2 - Nettoyage | Suppression de motif hex | `xxd` + `sed` |
| 2 - Extraction imbriquée | Binwalk puis tar | `binwalk`, `tar` |
| 3 - Lecture 3D | Projection orthographique + recherche d'angle | Blender, Online 3D Viewer, MeshLab |

## Pièges rencontrés

- **`unzip` vs AES** : le message « need PK compat. v5.1 » n'indique pas un
  fichier corrompu, juste que `unzip` ne supporte pas AES. Utiliser `7z`.
- **`xxd -p` multilignes** : oublier `tr -d '\n'` laisse des occurrences
  polluantes intactes. Le nettoyage paraît avoir fonctionné, mais l'étape
  suivante échoue sans raison apparente.
- **Double couche de pollution** : nettoyer uniquement le PNG ne suffit pas,
  il faut aussi nettoyer le `.gz` extrait.
- **Faux flags en 3D** : mais le joueur l'auras vite compris... J'espère ..