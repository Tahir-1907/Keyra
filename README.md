# Mon Coffre-Fort

Gestionnaire de mots de passe **local et hors ligne** pour Linux : interface de bureau
PySide6, un fichier SQLite par coffre, chiffrement Argon2id + AES-256-GCM. Aucun service
en ligne, aucune synchronisation, aucune télémétrie.

> **Version 1.7.0-rc1 — version candidate, pas une version finale.**
> Format de coffre : **schéma v4** (métadonnées chiffrées). Les coffres créés par les
> versions précédentes (schémas v1 à v3) sont mis à niveau **après confirmation explicite**
> (voir [Mise à niveau des anciens coffres](#mise-à-niveau-des-anciens-coffres-v1-à-v3)).
> Un coffre mis à niveau ne s'ouvre plus avec la version 1.6.

---

## Sommaire

* [Fonctionnalités](#fonctionnalités)
* [Installation](#installation)
* [Modèle de sécurité](#modèle-de-sécurité)
* [Ce qui est chiffré, ce qui reste lisible](#ce-qui-est-chiffré-ce-qui-reste-lisible)
* [Stockage et schéma v4](#stockage-et-schéma-v4)
* [Catégories, favoris, tags et recherche](#catégories-favoris-tags-et-recherche)
* [Historique et corbeille](#historique-et-corbeille)
* [Clé de récupération](#clé-de-récupération)
* [Sauvegardes (.mcfbak)](#sauvegardes-mcfbak)
* [Mise à niveau des anciens coffres (v1 à v3)](#mise-à-niveau-des-anciens-coffres-v1-à-v3)
* [Import et export](#import-et-export)
* [Sécurité au quotidien](#sécurité-au-quotidien)
* [Coffres multiples, utilisateurs, paramètres](#coffres-multiples-utilisateurs-paramètres)
* [Développement](#développement)
* [Tests](#tests)
* [Structure du projet](#structure-du-projet)
* [Limites connues](#limites-connues)
* [Feuille de route](#feuille-de-route)
* [Licence](#licence)

---

## Fonctionnalités

| Domaine | Ce que fait l'application |
|---|---|
| Coffres | Plusieurs coffres indépendants, chacun avec son mot de passe maître et sa clé de données |
| Entrées | 6 types : identifiant, note sécurisée, carte bancaire, identité, réseau Wi-Fi, serveur |
| Organisation | Catégories intégrées et personnelles, favoris, tags (20 au plus par entrée) |
| Recherche | Texte libre (sans tenir compte de la casse ni des accents) et `#tag` exact |
| Historique | 20 versions précédentes par entrée, restauration d'une version |
| Corbeille | Suppression restaurable, purge automatique réglable (30 jours par défaut) |
| Accès | Mot de passe maître, clé de récupération facultative, verrouillage automatique |
| Presse-papiers | Effacement automatique (30 s par défaut) des valeurs copiées |
| Générateur | Mots de passe et phrases de passe, estimation de robustesse hors ligne |
| Audit | Mots de passe faibles, réutilisés, anciens (> 1 an), absents, cartes expirées, entrées illisibles |
| Sauvegardes | Fichiers `.mcfbak` chiffrés, automatiques et manuels ; restauration en nouveau coffre |
| Import / export | Bitwarden, KeePassXC, Chrome, Firefox, CSV ; export chiffré, CSV, PDF |
| Mise à niveau | Coffres v1 à v3 → v4, avec préflight, confirmation, sauvegarde et vérification |

---

## Installation

### Paquet Debian

Le paquet se construit depuis les sources et ne déclare que des dépendances fournies par
Debian 13 (aucune bibliothèque embarquée). Le paquet `1.7.0~rc1` a été validé sur Debian 13
(voir [Tests](#tests)) : construction, inspection du contenu, installation **simulée**
(`apt-get -s`, sans nouvelle dépendance) et exécution de son code avec le Python et les
paquets du système. Il n'a pas été installé réellement pendant cette validation.

Procédure :

```bash
packaging/build-deb.sh                                        # -> dist/mon-coffre-fort_1.7.0~rc1_all.deb
sudo apt install ./dist/mon-coffre-fort_1.7.0~rc1_all.deb     # installe les dépendances Debian
```

* Version Debian : `1.7.0-rc1` devient `1.7.0~rc1`, ce qui garantit
  `1.6.0 < 1.7.0~rc1 < 1.7.0` pour `dpkg`.
* Dépendances : `python3 (>= 3.11)`, `python3-cryptography (>= 43)`,
  `python3-argon2 (>= 21.1)`, `python3-pyside6.*` (QtCore, QtGui, QtWidgets, QtNetwork,
  QtDBus, QtSvg, `>= 6.8`), `python3-pikepdf (>= 9.5)`, `hicolor-icon-theme`.
  Recommandés : `wfrench`, `wamerican`, `qt6-wayland`.
* Contenu : code dans `/usr/lib/mon-coffre-fort`, lanceur `/usr/bin/mon-coffre-fort`,
  entrée de menu et icônes. Le lanceur démarre Python en **mode isolé** (`python3 -I`) :
  ni `PYTHONPATH` ni un module du dossier personnel ne peuvent injecter de code.
* Le paquet n'exécute aucune migration de coffre : la mise à niveau éventuelle se fait
  à l'ouverture d'un coffre, après confirmation.
* Désinstallation : `sudo apt remove mon-coffre-fort`. Les coffres, sauvegardes et
  paramètres ne sont jamais supprimés par le paquet (même avec `purge`).
* Installer ce paquet **remplace** une version 1.6 installée de la même façon. Gardez de
  quoi réinstaller la 1.6 si vous voulez pouvoir rouvrir une sauvegarde faite avant la
  mise à niveau (voir [Irréversibilité](#irréversibilité)).

### Depuis les sources

Voir [Développement](#développement).

---

## Modèle de sécurité

### Clés

```text
mot de passe maître ──Argon2id (sel du coffre)──► KEK
KEK ──AES-256-GCM (déchiffrement)──► DEK : clé de données aléatoire de 256 bits
DEK ──AES-256-GCM──► secrets de chaque entrée (champ par champ), versions d'historique
DEK ──HKDF-SHA256──► sous-clés dédiées (métadonnées, catégories, sauvegardes)
```

* **Le mot de passe maître n'est jamais stocké.** Il sert à dériver la KEK, qui
  dé-enveloppe la DEK. Changer le mot de passe maître ré-enveloppe la DEK sans
  rechiffrer les données.
* **Argon2id** : 64 Mio de mémoire, 3 itérations, 4 lanes par défaut, sel aléatoire de
  16 octets par coffre. Les paramètres sont stockés avec le coffre et relus avec des
  bornes (1 Gio, 64 itérations, 64 lanes au plus) pour qu'un fichier piégé ne puisse
  pas bloquer l'application. Implémentation : celle de `cryptography` (versions 44 et
  plus), sinon `argon2-cffi` (paquet Debian `python3-argon2`, cas de Debian 13) ; les
  tests vérifient que les deux donnent la même clé (vecteurs de la RFC 9106).
* **AES-256-GCM** (chiffrement authentifié) : nonce aléatoire de **96 bits** tiré par
  `secrets` pour chaque chiffrement. Format d'un blob chiffré :
  `version (1 octet) | nonce (12 octets) | chiffré + tag GCM (16 octets)`.
* Aucune primitive cryptographique maison : uniquement `cryptography`, `argon2-cffi` et
  la bibliothèque standard. Le module `random` n'est importé nulle part dans `app/`
  (vérifié par un test).

### Sous-clés HKDF-SHA256

Chaque usage a sa propre clé, dérivée de la DEK (sans sel, domaine distinct) :

| Usage | Domaine (`info`) |
|---|---|
| Métadonnées des entrées | `mon-coffre-fort:entry-metadata:v1` |
| Noms des catégories personnelles | `mon-coffre-fort:category:v1` |
| Corps des sauvegardes `.mcfbak` | `mon-coffre-fort:backup:v1` |

Les secrets des entrées et les versions d'historique sont chiffrés directement avec la DEK.

### Données associées (AAD)

Chaque chiffré est lié à son contexte : déplacer un blob vers une autre entrée, un autre
champ, une autre version ou un autre coffre fait échouer l'authentification au lieu de
révéler la valeur ailleurs. Cette authentification porte sur chaque élément séparément :
elle ne couvre pas l'état global du coffre (retour à une ancienne version d'un élément,
suppression d'éléments), voir [Intégrité globale du coffre](#intégrité-globale-du-coffre).

| Donnée | AAD |
|---|---|
| Champ secret d'une entrée | `mon-coffre-fort:entry:<id>:<champ>` |
| Version d'historique | `mon-coffre-fort:history:<id entrée>:<id version>` |
| Métadonnées d'une entrée | `mon-coffre-fort:entry-metadata:<vault_uuid>:<id>` |
| Nom d'une catégorie personnelle | `mon-coffre-fort:category:<vault_uuid>:<id>` |
| DEK enveloppée (mot de passe / clé de récupération) | domaines distincts : une enveloppe ne peut pas remplacer l'autre |
| Sauvegarde `.mcfbak` | `MAGIC` + en-tête : toute modification de l'en-tête est détectée |
| Export chiffré `.mcfexport` | `mon-coffre-fort:export:v1` |

`vault_uuid` est un identifiant aléatoire de 16 octets, créé avec le coffre (ou à sa
mise à niveau), **lisible** dans le fichier et **immuable** : un déclencheur SQLite
refuse toute modification. Il ne change ni au changement de mot de passe, ni à la
récupération, ni à la sauvegarde puis restauration d'un coffre v4. Ce n'est pas un
secret : il lie les métadonnées chiffrées à leur coffre.

### Métadonnées en mémoire (`MetadataStore`)

Les métadonnées étant chiffrées, liste, recherche, filtres et tri se font **en mémoire**
après déchiffrement : SQLite ne contient aucun index ni jeton de recherche en clair.

* Un cache unique par coffre ouvert, partagé par tous les services, chargé
  paresseusement au premier accès (chaque blob n'est déchiffré qu'une fois).
* Toute écriture invalide l'élément concerné, relu depuis la base ; ce qui est lu
  pendant une transaction est relu après, pour qu'un ROLLBACK ne laisse jamais de valeur
  annulée en cache.
* Le verrouillage vide le cache et oublie la sous-clé de métadonnées. Rien n'est écrit
  sur disque.

### Détection d'erreurs

| Cas | Exception |
|---|---|
| Coffre inexistant | `VaultNotFoundError` |
| Mot de passe maître incorrect | `WrongMasterPasswordError` |
| Fichier illisible, structure invalide, vérificateur faux | `VaultCorruptedError` |
| Coffre créé par une version plus récente | `UnsupportedVaultVersionError` |
| Coffre v1 à v3 (mise à niveau nécessaire) | `VaultMigrationRequiredError` |
| Blob chiffré altéré ou déplacé | `EntryDecryptionError` / `CategoryDecryptionError` |

Un échec d'authentification de la DEK enveloppée est rapporté comme « mot de passe
incorrect » : cryptographiquement, il est indissociable d'une altération de ce blob.
Une entrée dont les métadonnées sont altérées n'empêche pas l'ouverture du coffre :
elle est mise à l'écart et signalée par l'audit.

### Ce que l'application ne fait pas

* Stocker un mot de passe (maître ou d'entrée) en clair sur disque.
* Journaliser un secret : les journaux ne contiennent que des identifiants de coffre,
  des compteurs, des noms de fichiers et des types d'erreur ; un filtre de masquage
  s'ajoute en défense en profondeur.
* Accéder au réseau.

### Limite de la mémoire Python

CPython ne permet pas d'effacer de façon garantie une chaîne en mémoire (copies
internes, ramasse-miettes, swap). L'application efface au mieux les tampons qu'elle
contrôle (`crypto.wipe()` sur la DEK), supprime les références dès qu'elles ne servent
plus (par exemple le mot de passe maître capturé par la fenêtre de mise à niveau), mais
ne peut pas garantir que le contenu a disparu de la mémoire.

---

## Ce qui est chiffré, ce qui reste lisible

Le coffre n'est pas un fichier « opaque » : certaines informations restent lisibles par
conception.

| Chiffré | Lisible sans mot de passe |
|---|---|
| Mots de passe, e-mails, notes, champs spécifiques (numéro de carte, CVV, PIN…) | Nom du coffre, dates de création et de modification du coffre |
| Nom, URL, identifiant, type, catégorie, favori, tags de chaque entrée | Versions du schéma et du format, paramètres Argon2id, sels |
| Dates de création, modification, changement de mot de passe, mise en corbeille | DEK enveloppée(s) et vérificateur (chiffrés, mais visibles comme blobs) |
| Contenu complet de chaque version d'historique | `vault_uuid` |
| Noms des catégories personnelles | Clés techniques des catégories intégrées (`personal`, `work`…), communes à tous les coffres |
| Corps des sauvegardes `.mcfbak` et des exports `.mcfexport` | **`entry_history.created_at`** : date d'enregistrement de chaque version (décision D3) |
| | Nombre d'entrées, de catégories et de versions ; lien version → entrée ; compteurs AUTOINCREMENT |
| | Taille approximative des métadonnées (arrondie à 64 octets) |
| | En-tête des fichiers `.mcfbak` (voir [Sauvegardes](#sauvegardes-mcfbak)) |

**Décision D3** : `entry_history.created_at` reste en clair pour ordonner l'historique
et appliquer son plafond (20 versions) sans rien déchiffrer. Conséquence : pour une
entrée modifiée, la date de sa dernière modification se déduit de cette colonne.

---

## Stockage et schéma v4

```text
~/.config/mon-coffre/settings.json              # paramètres (aucun secret), 0600
~/.local/share/mon-coffre/
├── vaults/<identifiant-du-coffre>/vault.db     # un fichier SQLite par coffre
└── logs/mon-coffre.log
<Documents>/MonCoffre/backup/                   # sauvegardes .mcfbak (dossier réglable)
```

Tables d'un coffre v4 :

| Table | Contenu |
|---|---|
| `vault_meta` | paramètres Argon2id, sel, DEK enveloppée, vérificateur, `vault_uuid`, nom du coffre |
| `vault_recovery` | seconde enveloppe de la DEK (clé de récupération), facultative |
| `entries` | `id`, `metadata_enc`, `email_enc`, `password_enc`, `notes_enc`, `extra_fields_enc` |
| `categories` | `id`, `builtin_key` (catégorie intégrée) **ou** `name_enc` (catégorie personnelle) |
| `entry_history` | `id`, `entry_id`, `snapshot_enc`, `created_at` |

* **`metadata_enc`** : JSON chiffré et versionné regroupant nom, URL, identifiant, type,
  catégorie, favori, tags, dates de création, de modification, de changement de mot de
  passe et de mise en corbeille. Relu avec une **validation stricte** : clés exactes,
  types, dates ISO 8601 avec fuseau, tags canoniques. Toute anomalie est traitée comme
  une corruption, jamais comblée par une valeur par défaut. Remplissage à un multiple
  de 64 octets pour réduire, sans la supprimer, la fuite de longueur.
* Les champs vides sont chiffrés aussi : on ne voit pas quelles entrées ont un mot de
  passe ou des notes.
* La table `entry_tags` des schémas v1 à v3 n'existe plus en v4 : les tags sont dans
  `metadata_enc`. Elle n'est lue que par la migration.
* `PRAGMA secure_delete = ON` (les pages libérées sont remises à zéro), mode WAL,
  `umask 077` : coffres, WAL et journaux sont créés en `0600`, les dossiers en `0700`.
  Les fichiers exportés sont écrits de façon atomique (fichier temporaire, `fsync`,
  renommage).

---

## Catégories, favoris, tags et recherche

* **Catégories intégrées** : Personnel, Travail, Finances, Réseaux sociaux, Courriel,
  Achats. Stockées par clé technique (`builtin_key`), ni renommables ni supprimables.
* **Catégories personnelles** : nom chiffré (60 caractères au plus, unique sans tenir
  compte de la casse ni des accents). Supprimer une catégorie ne supprime aucune
  entrée : ses entrées (corbeille comprise) passent « sans catégorie », dans la même
  transaction.
* **Favoris** : dans les métadonnées chiffrées ; changer le favori ne crée pas de
  version d'historique.
* **Tags** : 20 au plus par entrée, 32 caractères au plus. Espaces normalisés, `#`
  initial retiré, forme saisie conservée. Refusés : tag vide, virgule, caractère de
  contrôle ou invisible, doublon logique (sans tenir compte de la casse ni des
  accents : `Linux` = `linux`, `École` = `ecole`). Éditeur à puces dans la fiche d'un
  compte, avec complétion à partir des tags existants. Les tags s'affichent en badges
  dans le détail ; un clic lance la recherche de ce tag.
* **Recherche** (en-tête, appliquée 150 ms après la dernière frappe) :
  * le texte libre porte sur le nom, l'identifiant, l'URL, la catégorie et les tags,
    sans tenir compte de la casse ni des accents ; tous les mots doivent être présents ;
  * `#linux` sélectionne les entrées portant exactement ce tag (casse et accents
    ignorés : `#ecole` trouve `École`) ; `#"écoles primaires"` pour un tag avec espaces ;
    plusieurs `#` se combinent en ET, et avec le texte libre ;
  * un `#` seul est ignoré ; `C#` reste du texte ordinaire ;
  * les secrets (mots de passe, notes…) ne sont jamais recherchés.

---

## Historique et corbeille

* **Historique** : chaque modification du contenu d'une entrée conserve la version
  précédente complète (ancien mot de passe compris), chiffrée ; 20 versions au plus
  par entrée. Une modification des seuls tags crée une version ; le favori, non.
  Restaurer une version place la version actuelle dans l'historique. La version
  restaurée reprend ses propres tags ; une version enregistrée avant la 1.7 (format
  sans tags) conserve les tags actuels. Le favori actuel est conservé. On peut effacer
  l'historique d'une entrée.
* **Corbeille** : supprimer une entrée la place dans la corbeille (restaurable). Les
  entrées y sont purgées à l'ouverture du coffre au-delà de 30 jours (réglable : 7, 30,
  90 jours, 1 an, jamais) ; la date de mise en corbeille est lue dans les métadonnées
  chiffrées. La suppression définitive efface aussi l'historique. Les entrées en
  corbeille ne sont ni recherchées dans la vue Coffre, ni exportées ; l'audit ne les
  analyse pas, sauf pour signaler celles dont les métadonnées sont illisibles.

---

## Clé de récupération

Facultative, proposée à la création d'un coffre (ou depuis Paramètres → Ce coffre).

* **Format** : 32 caractères en 8 groupes de 4 (base32 de Crockford), dont 150 bits
  aléatoires et 2 caractères de contrôle qui signalent une faute de frappe. Saisie
  tolérante (casse, espaces, tirets, confusions O/0 et I/L/1).
* **Seconde enveloppe de la DEK** : clé → Argon2id (sel propre) → AES-256-GCM, table
  `vault_recovery`. La clé n'est jamais stockée et n'est affichée qu'une fois ; elle
  peut être enregistrée dans un PDF toujours chiffré (AES-256, mot de passe fort exigé,
  différent du mot de passe maître).
* **Affichage confirmé** : si la fenêtre se ferme sans confirmation que la clé a été
  notée, la clé est supprimée du coffre.
* **Mot de passe oublié** : clé + nouveau mot de passe maître. La nouvelle enveloppe du
  mot de passe et une **nouvelle** clé sont écrites dans une même transaction ;
  **l'ancienne clé ne fonctionne plus**.
* **Créer, remplacer, supprimer** la clé exige le mot de passe maître.
* **Coffre v1 à v3 et mot de passe oublié** : la récupération passe par la mise à
  niveau, confirmée au préalable. Le préflight a lieu **avant** toute écriture, puis :
  récupération (nouveau mot de passe, nouvelle clé), sauvegarde, migration,
  vérification, ouverture. Si la récupération réussit mais que la migration échoue, le
  coffre reste dans son format d'origine, intact, avec le nouveau mot de passe et la
  nouvelle clé : **la nouvelle clé est affichée quand même** et reste valide même si
  la fenêtre est fermée sans l'avoir notée (elle peut être remplacée une fois le coffre
  ouvert). Pour réessayer, il suffit de déverrouiller avec le nouveau mot de passe.
* Une sauvegarde s'ouvre avec le mot de passe maître en vigueur lors de la sauvegarde ;
  la clé de récupération sert au coffre restauré, pas au fichier `.mcfbak`.

---

## Sauvegardes (.mcfbak)

```text
MAGIC (8 o) | longueur de l'en-tête (4 o) | en-tête JSON | nonce (12 o)
            | AES-256-GCM( zlib( base SQLite complète ) )
```

* **Corps chiffré** : la base complète (entrées, métadonnées, historique, catégories),
  compressée puis chiffrée avec la sous-clé HKDF de sauvegarde. L'en-tête est
  authentifié (donnée associée) : il ne peut pas être modifié sans être détecté.
* **En-tête lisible sans mot de passe** : identifiant et nom du coffre, type et date de
  la sauvegarde, version de l'application, versions du schéma et du format, paramètres
  Argon2id, sel, DEK enveloppée et vérificateur. Une sauvegarde n'est donc pas un
  fichier « opaque » : ces informations sont visibles, le contenu des comptes ne l'est
  pas. Elle peut être copiée sur un support externe ou un dossier synchronisé en
  connaissance de cause.
* **Autonome** : elle s'ouvre avec le mot de passe maître **en vigueur au moment où elle
  a été faite**, même si le coffre d'origine a disparu.
* **Automatiques** au verrouillage et à la fermeture si le coffre a été modifié pendant
  la session (10 conservées par défaut, réglable de 1 à 100) ; **manuelles** ; **de
  migration**, créées avant une mise à niveau, jamais supprimées automatiquement.
* **Restauration** : crée toujours un **nouveau** coffre « … (restauré le …) », vérifié
  avant d'être proposé ; rien n'est écrasé. Une sauvegarde d'un coffre v1 à v3 est
  restaurée telle quelle, puis sa mise à niveau est **proposée** à sa première ouverture
  (même processus qu'un ancien coffre).
* **Suppression** depuis la page Sauvegardes : l'en-tête est relu avant, un fichier qui
  n'est pas une sauvegarde de ce coffre n'est jamais effacé.

---

## Mise à niveau des anciens coffres (v1 à v3)

La mise à niveau n'est **jamais automatique**. Elle est proposée au déverrouillage d'un
coffre créé par une version précédente, une fois le mot de passe vérifié :

```text
détection (VaultMigrationRequiredError, mot de passe déjà vérifié)
    ↓
inspection en lecture seule + préflight strict
    ↓
confirmation explicite (Annuler = coffre inchangé)
    ↓
sauvegarde chiffrée .mcfbak « migration », vérifiée par déchiffrement complet
    ↓
migration en une seule transaction (tout ou rien), puis VACUUM
    ↓
ouverture normale et vérification complète
    ↓
session v4
```

* **Préflight** : toute structure SQLite que Mon Coffre-Fort n'a pas créée (table, vue,
  déclencheur, index ou colonne inattendus) **refuse** la mise à niveau. Rien n'est
  supprimé ni ignoré en silence ; le coffre n'est pas modifié.
* **Migration** (`app/services/migration_v4.py`) : mise à jour structurelle historique
  v1/v2 → v3 (pour les plus anciens coffres, dans la même transaction), génération de
  `vault_uuid`, chiffrement et relecture de chaque métadonnée comparée à la source,
  catégories, tags hérités de `entry_tags`, validation de chaque version d'historique,
  comparaison des listes et des compteurs, reconstruction des tables sans aucune
  colonne en clair, contrôles d'intégrité, `schema_version = 4` en dernier. Toute erreur
  annule tout (ROLLBACK) ; un arrêt brutal du processus pendant la transaction laisse le
  coffre dans son format d'origine (testé par SIGKILL).
* **Historique illisible, secret altéré, incohérence** : la mise à niveau est refusée et
  le coffre reste intact. Rien n'est jamais supprimé pour « faire passer » une migration.
* **Vérification complète** avant d'ouvrir la session : structure v4 exacte, intégrité
  SQLite, chaque métadonnée, catégorie, secret et version d'historique relus, sauvegarde
  de migration revérifiée.
* En cas d'échec, l'erreur est affichée (avec chemin et cause pour un problème de
  sauvegarde) et un nouvel essai est possible. Pendant le travail, qui s'exécute hors
  du fil de l'interface, la fenêtre et l'application ne peuvent pas être fermées.
* **Anciennes copies en clair** (`vault.db.avant-schema-v*.bak`, laissées par les
  versions 1.x à côté du coffre) : signalées, jamais utilisées ni supprimées. À supprimer
  soi-même une fois le coffre vérifié.

### Irréversibilité

Un coffre mis à niveau ne s'ouvre plus avec une version 1.6. La sauvegarde de migration,
elle, est dans le format d'origine et s'ouvre avec le mot de passe maître de l'époque :
pour revenir en arrière, il faut une version 1.6 et sa fonction « Restaurer une
sauvegarde », qui crée un nouveau coffre (compatibilité testée avec le code 1.6.0).

---

## Import et export

Menu « Plus » ou palette de commandes (`Ctrl+K`). L'export redemande le mot de passe
maître. Les fichiers sont créés en `0600`. Ni la corbeille ni l'historique ne sont exportés.

| Format | Import | Export | Tags |
|---|---|---|---|
| Bitwarden, KeePassXC, Chrome / Chromium / Edge / Brave, Firefox (CSV) | oui | — | — |
| CSV générique (`name`/`title`, `url`, `username`, `password`…) | oui | — | — |
| CSV Mon Coffre-Fort | oui | oui (**non chiffré**) | colonne `tags` facultative |
| Export chiffré `.mcfexport` | oui | oui | oui |
| Copie papier PDF | — | oui | **non** |

* **Import** : aperçu sans les mots de passe, catégories créées à partir des
  dossiers/groupes, doublons détectés, import en une seule transaction ; 20 Mo au plus.
  Un tag invalide ou en double est écarté (l'entrée est importée) et leur nombre est
  affiché. Après l'import d'un CSV, l'application propose de supprimer le fichier. Les
  fichiers `.kdbx` ne sont pas lus directement : exportez-les d'abord en CSV.
* **`.mcfexport`** : JSON chiffré en AES-256-GCM avec une clé Argon2id dérivée d'un
  **mot de passe d'export** distinct.
* **CSV** : mots de passe en clair ; avertissement et confirmation obligatoires.
* **PDF** : comptes actifs classés par catégorie, construit en mémoire. Protégé par
  défaut (AES-256 via `python3-pikepdf`, mot de passe différent du mot de passe maître) ;
  si pikepdf manque, l'option est désactivée, jamais de repli silencieux vers un PDF
  en clair.

---

## Sécurité au quotidien

* **Presse-papiers** : valeurs sensibles effacées après 30 s (10 s à 5 min), au
  verrouillage et à la fermeture, seulement si le presse-papiers contient encore notre
  valeur (empreinte HMAC à clé éphémère). Sélection X11 nettoyée ; indicateur
  `x-kde-passwordManagerHint: secret` pour les gestionnaires d'historique (qui ne le
  respectent pas tous).
* **Verrouillage automatique** : après 5 minutes d'inactivité par défaut (1, 5, 10,
  30 min, 1 h ou jamais), au verrouillage de la session et à la mise en veille (D-Bus).
  Le verrouillage ferme les fenêtres ouvertes, nettoie le presse-papiers, détruit la
  vue et efface la DEK.
* **Générateur** : mots de passe de 8 à 128 caractères, phrases de passe de 4 à 12 mots
  (liste française de `wfrench`) ; tirages par `secrets`, entropie exacte affichée.
* **Robustesse** : estimation hors ligne (mots courants, dictionnaires, « leet »,
  années, répétitions, suites, rangées de clavier) ; c'est une estimation, pas une
  garantie.
* **Audit** : entièrement local ; le rapport ne contient aucun secret. Pas de
  vérification de fuite en ligne.

---

## Coffres multiples, utilisateurs, paramètres

* Chaque coffre est un fichier indépendant. Écran de verrouillage avec la liste des
  coffres (le dernier utilisé est présélectionné). Renommer, changer le mot de passe
  maître (suivi d'une sauvegarde protégée par le nouveau), supprimer (nom + mot de passe
  maître exigés ; les sauvegardes ne sont pas supprimées).
* **Un compte Linux par personne** recommandé. L'application refuse de démarrer en root
  et vérifie que ses dossiers appartiennent à l'utilisateur. Une seule instance par
  utilisateur (socket local réservé au propriétaire). Les noms des coffres sont visibles
  sur l'écran de verrouillage.
* **Paramètres** (`Ctrl+,`) : verrouillage, effacement du presse-papiers, corbeille,
  sauvegardes automatiques (nombre, dossier), générateur. Le fichier est validé à la
  lecture : toute valeur inconnue revient à sa valeur par défaut.
* **Raccourcis** : `Ctrl+N` nouveau, `Ctrl+E` modifier, `Ctrl+D` dupliquer, `Ctrl+C` /
  `Ctrl+B` copier mot de passe / identifiant, `Ctrl+F` rechercher, `Ctrl+K` palette,
  `Ctrl+G` générateur, `Ctrl+L` verrouiller, `Alt+1`…`Alt+6` vues, `F1` aide, `F11`
  plein écran, `Ctrl+Q` quitter.

---

## Développement

Python **3.11 ou plus** (valeur retenue par Ruff et par la dépendance du paquet Debian ;
aucune syntaxe postérieure à 3.11 dans `app/`). SQLite via la bibliothèque standard,
sans ORM.

```bash
git clone <dépôt>
cd mon-coffre-fort
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt        # exécution : cryptography>=44, PySide6-Essentials>=6.8, pikepdf>=9.5
pip install -r requirements-dev.txt    # + argon2-cffi, pytest, coverage, ruff
python -m app.main                     # ou ./run.sh (crée l'environnement au premier lancement)
```

Optionnels : `wfrench` (phrases de passe) et `wamerican` (estimation de robustesse).

Il n'y a pas de table `[project]` dans `pyproject.toml` : l'application n'est pas un
paquet pip ; sa version a une source unique, `__version__` dans `app/__init__.py`, lue
par `packaging/build-deb.sh`.

---

## Tests

```bash
QT_QPA_PLATFORM=offscreen pytest
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -p 'test_*.py'
ruff check .
```

* **543 tests et 188 sous-tests**, compatibles pytest et unittest (tous réussis, Ruff
  propre, dans l'environnement indiqué plus bas). Il n'y a pas d'intégration continue :
  les suites se lancent localement.
* Ruff sert aussi d'analyse de sécurité : règles `S` (celles de Bandit), `PLE2502`
  (Unicode trompeur) et `S4xx` (imports sensibles). Chaque exception (`noqa`) est
  justifiée sur sa ligne.
* Principales suites : cryptographie et vecteurs Argon2id, coffre, entrées,
  métadonnées v4 et cache, catégories, tags, historique, corbeille, sauvegardes,
  import/export, PDF, sécurité (fichiers piégés, altérations, fuites), interface Qt en
  mode `offscreen`, migration (retour arrière à chaque étape, SIGKILL dans et hors
  transaction, structures inattendues, confidentialité au niveau des octets),
  compatibilité de la sauvegarde de migration avec le code 1.6.0.
* **Coffres de référence** : `tests/fixtures/v2-app-1.0.0` et `v3-app-1.6.0`, produits par
  les versions 1.0.0 et 1.6.0, données entièrement fictives ; les tests travaillent sur
  des copies et vérifient que ces fichiers ne changent jamais.
* Certains tests sont ignorés proprement si un outil manque : PySide6, `pdftotext`,
  `pikepdf`, `wfrench`, argon2-cffi, ou le commit `a99f821` (compatibilité 1.6.0).
* Quelques tests vérifient des durées (chargement de 2 000 entrées, par exemple) : sur
  une machine très lente, ils peuvent échouer sans défaut du code.
* Environnements de validation :
  * **développement** (`.venv`) : Debian 13, Python 3.13.5, PySide6 6.11.2,
    cryptography 50.0.1, argon2-cffi 21.1.0, pikepdf 9.11.0, SQLite 3.46.1 ; pytest et
    unittest (543 tests, 188 sous-tests), Ruff ;
  * **paquets Debian 13** (ceux du `.deb`) : Python système 3.13.5, PySide6 6.8.2.1 /
    Qt 6.8.2, cryptography 43.0.0, argon2-cffi 21.1.0, pikepdf 9.5.2, SQLite 3.46.1 ;
    `python3 -m unittest` : 543 tests réussis, 3 ignorés comme attendu (ils exigent
    `cryptography` 44 ou plus, ou les deux implémentations d'Argon2id, et tournent dans
    l'environnement de développement).
* **Dépendance de test uniquement** : sous Debian 13, les tests d'interface utilisent
  `PySide6.QtTest`, fourni par `python3-pyside6.qttest` (et `libqt6test6`). L'application
  ne l'utilise pas et le paquet `.deb` ne l'exige pas. Pour la validation ci-dessus, ces
  deux paquets ont été téléchargés et utilisés hors du système, sans être installés.

---

## Structure du projet

```text
app/
├── core/          logique métier, sans interface ni SQL
│                  crypto (Argon2id, AES-GCM, HKDF), vault (cycle de vie, récupération),
│                  metadata (JSON chiffré v4, tags), metadata_store (cache), entries,
│                  categories, snapshots (historique), audit, generator, strength, session
├── database/      SQLite : schéma et contrôles de structure, modèles, repositories
├── services/      opérations sur fichiers : backup, import_export, pdf_export, settings,
│                  migration_v4 (moteur tout ou rien), vault_upgrade (préflight,
│                  orchestration, vérification)
├── ui/            PySide6 : fenêtres, vues (pages/), dialogues, tag_editor,
│                  migration_dialog, presse-papiers, verrouillage système, tâches de fond
├── resources/     logo, police Inter (OFL), icônes Lucide (ISC)
└── utils/         chemins XDG, journalisation, écriture atomique
tests/             tests unittest/pytest et coffres de référence (fixtures/)
packaging/         build-deb.sh, entrée de menu .desktop
```

L'interface ne touche jamais SQLite ni la cryptographie : elle passe par `core/` et
`services/`. `database/` ne manipule que des octets déjà chiffrés et ne connaît aucune clé.

---

## Limites connues

### Intégrité globale du coffre

La version 1.7.0-rc1 authentifie chaque donnée chiffrée **individuellement** (AES-256-GCM,
nonce aléatoire, AAD liant chaque blob à son entrée, son champ, sa version, sa catégorie
ou son coffre, clés séparées par usage), mais le coffre ne possède pas encore de
**manifeste authentifié représentant son état global**.

Une personne capable de modifier directement le fichier SQLite peut donc, dans certaines
conditions, faire accepter sans alerte des changements de l'état logique du coffre
(constaté sur un coffre de test) :

* remettre une entrée dans un état antérieur, à partir d'une ancienne copie du fichier ;
* supprimer une entrée ou des versions d'historique ;
* modifier des données techniques non chiffrées, comme les dates d'historique (D3) ;
* échanger les clés techniques de catégories intégrées (une entrée « Travail » apparaît
  alors dans « Finances »).

Cette limitation concerne l'**intégrité globale** (retour arrière, suppression), pas la
confidentialité. Elle ne permet pas de lire les mots de passe ni de déchiffrer les
secrets, ne permet pas de fabriquer des données chiffrées valides, et ne contourne pas
l'authentification AES-GCM : un blob modifié ou déplacé hors de son contexte est détecté.
Un mécanisme d'intégrité globale authentifié est prévu pour une évolution après la RC1 ;
il demandera une conception dédiée (format, migration, compatibilité).

### Tableau récapitulatif

| Limite | Effet | Statut |
|---|---|---|
| Intégrité globale | Retour arrière ou suppression d'éléments par écriture directe dans le fichier, non détectés (voir ci-dessus) | Après RC1 |
| `entry_history.created_at` en clair (D3) | Dates des versions (donc de la dernière modification d'une entrée modifiée) lisibles dans le fichier | Choix de conception |
| Métadonnées techniques lisibles | Nom du coffre, nombre d'entrées/catégories/versions, taille approximative, en-tête `.mcfbak` (voir plus haut) | Choix de conception |
| Échec du VACUUM après migration | La migration est conservée et vérifiée ; un nouvel essai a lieu à la vérification ; s'il échoue aussi, un avertissement est affiché : d'anciennes pages libres restent dans le fichier (remises à zéro par `secure_delete` lors de nos essais, sans garantie formelle) | Connu |
| Échec de la vérification finale après une migration validée | Le coffre (déjà v4) n'est pas ouvert et la sauvegarde de migration est conservée ; une ouverture ultérieure l'ouvrira normalement, sans nouvelle vérification complète | Après RC1 |
| Sauvegardes de migration | Chaque tentative de mise à niveau crée une sauvegarde, jamais supprimée automatiquement | Après RC1 |
| Presse-papiers et veille | Le délai d'effacement ne compte pas le temps de veille ; sans effet si « verrouiller à la veille » est actif (réglage par défaut), car le verrouillage efface le presse-papiers | Après RC1 |
| Exports interrompus | Après un arrêt brutal pendant un export, un fichier temporaire `.tmp-export-*` (en clair pour un CSV ou un PDF non protégé) peut rester dans le dossier de destination | Après RC1 |
| CSV exporté | Les valeurs commençant par `=`, `+`, `-` ou `@` ne sont pas neutralisées (formules dans un tableur) | Après RC1 |
| PDF | Les tags ne figurent pas dans la copie papier | Après RC1 |
| Recherche `#` | Un tag contenant à la fois un guillemet et un espace à certains endroits (ex. `a" b`) ne peut pas être recherché exactement | Marginal |
| Tags d'une version antérieure à la 1.7 | Affichée, elle reprend les tags de la version plus récente ; restaurée, elle garde les tags actuels | Choix documenté |
| Mémoire Python | Pas d'effacement garanti des chaînes (voir plus haut) | Limite du langage |
| Récupération d'un ancien coffre | Si la mise à niveau qui suit une récupération était interrompue par une exception système (hors erreur applicative), la nouvelle clé ne serait pas affichée ; aucun cas atteignable n'est connu dans l'interface | Après RC1 |
| Hors ligne par conception | Pas de coffre partagé ni de synchronisation | Hors périmètre |

---

## Feuille de route

**Préparation de la RC1** : faite (validation Debian 13, construction et inspection du
paquet, audit final).

**Après la RC1** (non implémenté) : manifeste d'intégrité globale authentifié du coffre ;
tags dans le PDF ; délai du presse-papiers tenant
compte de la veille ; nettoyage des temporaires d'export après un arrêt brutal ;
neutralisation des formules dans l'export CSV ; gestion des sauvegardes de migration
multiples ; revérification après un échec de vérification post-migration ; lecture de
l'en-tête seul lors du listage des sauvegardes ; recherche `#` des tags avec guillemet et
espace ; coffre de référence v4 pour les tests de futures migrations ; contrôle du paquet
par `lintian`.

---

## Licence

Tous droits réservés : aucune licence open source n'a été choisie pour ce projet
personnel (voir `LICENSE`). Composants tiers inclus : police Inter (SIL Open Font
License 1.1) et icônes Lucide (ISC), avec leurs textes de licence dans `app/resources/`.
