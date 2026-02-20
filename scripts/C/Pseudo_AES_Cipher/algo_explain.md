L'algorithme décrit ci-dessous vient du challenge "Pseudo AES" de cyberwave:
<https://training.cyberwave.network/challenges>

# Analyse Cryptographique et Stratégie de Crackage

## 1. Vue d’ensemble de l’algorithme de chiffrement

L’algorithme opère sur un bloc fixe de 64 octets, découpé en 4 sous-matrices 4x4 (M1 à M4). Chaque sous-matrice subit les opérations suivantes :

1. Renversement horizontal des colonnes.
2. XOR coefficient par coefficient avec une matrice clé K (4x4).
3. Addition d’une constante égale à trace(K) / 2.
4. Symétrie centrale (inversion des indices).
5. Écriture séquentielle des matrices.

L’ensemble constitue une transformation déterministe appliquée indépendamment sur chaque sous-matrice.

---

## 2. Analyse des Faiblesses Structurelles

### 2.1 Linéarité Globale

Les seules opérations utilisées sont :

* Permutations (renversement + symétrie)
* XOR
* Addition modulo 256

Ces opérations sont linéaires.

Il n’existe :

* aucune non-linéarité
* aucun mécanisme de diffusion inter-bloc

L’algorithme peut être modélisé sous la forme :

C = P2( ( P1(M) ⊕ K ) + t )

avec t = trace(K)/2.

Il s’agit donc d’un chiffrement non linéaire donc prévisible.

---

### 2.2 Absence de Diffusion

Chaque sous-matrice est traitée indépendamment.

Une modification d’un octet en entrée n’affecte qu’un seul octet en sortie (après permutation).

L’effet avalanche est inexistant

---

### 2.3 Vulnérabilité Known-Plaintext

Avec un couple clair/chiffré :

1. On annule les permutations.
2. On retire la constante.
3. On obtient directement M ⊕ K.
4. On déduit K.

La clé complète peut être reconstruite à partir d’un seul bloc connu.

---

## 3. Stratégie de Déchiffrement (Clé Connue)

Le déchiffrement consiste à appliquer les opérations inverses dans l’ordre inverse.

Ordre inverse :

1. Appliquer la symétrie centrale.
2. Soustraire trace(K)/2 (mod 256).
3. Appliquer le XOR avec la clé.
4. Annuler le renversement horizontal.

Formellement :

M = P1⁻¹( ( P2⁻¹(C) - t ) ⊕ K )

---

## 4. Conclusion Sécurité

Cet algorithme ne fournit pas de sécurité cryptographique réelle.

Il s’agit d’une construction pédagogique illustrant :

* la réversibilité d’opérations linéaires
* l’importance de la non-linéarité et de la diffusion en cryptographie moderne

