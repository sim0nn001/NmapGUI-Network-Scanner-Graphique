# ⬡ NmapGUI — Network Scanner Graphique

Interface graphique GTK3 pour nmap, développée en C++17.

## Fonctionnalités

| Fonctionnalité | Détail |
|---|---|
| Scan réseau complet | IP, hostname, statut (up/down) |
| Détection de ports | État, protocole, service, version/banner |
| Détection d'OS | Via `--osscan-guess` |
| Adresse MAC & fabricant | Résolution automatique |
| Latence | Mesurée par nmap |
| Types de scan | Ping, TCP, SYN, UDP, Service, OS, Agressif |
| Timing | T0 (furtif) à T5 (insane) |
| Sortie brute | Affichage de la sortie nmap originale |
| Export CSV | Export de tous les résultats |

## Dépendances

```bash
sudo apt install nmap libgtk-3-dev g++ pkg-config
```

## Compilation

```bash
make
```

## Utilisation

```bash
# Scan TCP Connect (sans root)
./nmap_gui

# Scan SYN, détection OS (nécessite root)
sudo ./nmap_gui
```

### Exemples de cibles

| Cible | Description |
|---|---|
| `192.168.1.0/24` | Sous-réseau complet |
| `192.168.1.1-50` | Plage d'adresses |
| `scanme.nmap.org` | Hôte de test officiel nmap |
| `10.0.0.1` | Hôte unique |

## Architecture

```
nmap_scanner.cpp
├── HostInfo / PortInfo      — Structures de données
├── parse_nmap_output()      — Parser regex de la sortie nmap
├── scan_thread()            — Thread de scan (non-bloquant)
├── on_scan_done_main_thread() — Mise à jour UI thread-safe via g_idle_add
├── build_control_panel()    — Panneau gauche (paramètres)
├── build_host_tree()        — Tableau des hôtes
├── build_port_tree()        — Tableau des ports
├── build_raw_view()         — Vue texte brut
└── main()                   — GTK init + CSS + fenêtre principale
```

## Notes de sécurité

- Le scan SYN (`-sS`) et la détection d'OS (`-O`) nécessitent `sudo`
- N'utilisez cet outil que sur des réseaux dont vous avez l'autorisation
- Le timer T5 (Insane) peut saturer un réseau
