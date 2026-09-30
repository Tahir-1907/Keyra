"""Generates a test vault with an EXISTING version of the application.

Used by the migration tests: the vaults in tests/fixtures/ were produced by the
real code of earlier versions (not imitated), with 100% fictitious data (in
French, as the application was at the time). Run it only on the code of the
version to freeze:

    # schema v2 vault, produced by Mon Coffre-Fort 1.0.0 (the application's former name)
    python tests/fixtures/generate_v16_fixtures.py <root-1.0.0> tests/fixtures/v2-app-1.0.0
    # schema v3 vault, produced by Mon Coffre-Fort 1.6.0 (commit 2d4fde0)
    python tests/fixtures/generate_v16_fixtures.py . tests/fixtures/v3-app-1.6.0

The manifest (manifest.json) describes the expected content after decryption and
the search results computed BY THAT VERSION: after migration, the new version
must return exactly the same data and results.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

MASTER_PASSWORD = "fixture-mot-de-passe-maitre-FICTIF"
VAULT_ID = "coffre-fixture"
VAULT_NAME = "Coffre de test (fictif)"
OLD_DELETION = "2001-01-01T00:00:00+00:00"


def main(app_root: str, output: str) -> None:
    work = Path(tempfile.mkdtemp(prefix="mcf-fixture-"))
    os.environ["XDG_DATA_HOME"] = str(work / "data")
    os.environ["XDG_CONFIG_HOME"] = str(work / "config")
    sys.path.insert(0, str(Path(app_root).resolve()))

    from app import __version__
    from app.core.categories import CategoryService
    from app.core.entries import Entry, EntryFilter, EntryService
    from app.core.vault import Vault
    from app.database import database

    if hasattr(Vault, "create_with_recovery"):
        vault, recovery_key = Vault.create_with_recovery(VAULT_ID, VAULT_NAME, MASTER_PASSWORD)
    else:
        vault, recovery_key = Vault.create(VAULT_ID, VAULT_NAME, MASTER_PASSWORD), None
    entries, categories = EntryService(vault), CategoryService(vault)
    categories.ensure_builtin_categories()
    cat = {c.name: c.id for c in categories.list_categories()}
    cat["Projets BTS"] = categories.create_category("Projets BTS")
    cat["Santé & Mutuelle"] = categories.create_category("Santé & Mutuelle")
    doomed = categories.create_category("Catégorie supprimée")

    def add(**fields) -> int:
        return entries.create_entry(Entry(**fields))

    bank = add(service_name="Banque Exemple", url="https://banque.example/connexion",
               username="jean.dupont@example.test", email="jean.dupont@example.test",
               password="Mdp-Banque-FICTIF-001", notes="Code client : 000000 (fictif)",
               category_id=cat["Finances"], is_favorite=True)
    forum = add(service_name="Forum Linux", url="forum.example.org",
                username="tux_fictif", password="Tux-FICTIF-002", category_id=cat["Projets BTS"])
    add(service_name="Éléphant Café", url="https://cafe.example", username="client.cafe",
        password="Cafe-FICTIF-003", category_id=cat["Achats"])
    add(service_name="Note Wi-Fi invités", entry_type="secure_note",
        notes="Réseau invités : demander au bureau (fictif)", category_id=cat["Personnel"])
    add(service_name="Carte Fictive", entry_type="card", category_id=cat["Finances"],
        extra={"cardholder": "JEAN DUPONT", "card_number": "4111 1111 1111 1111",
               "expiry": "12/2030", "cvv": "123", "pin": "0000"}, is_favorite=True)
    add(service_name="Box Maison", entry_type="wifi", password="Wifi-FICTIF-004",
        extra={"ssid": "BoxFictive-5G", "security": "WPA3"})
    add(service_name="Serveur Debian", entry_type="server", url="ssh://srv.example",
        username="admin-fictif", password="Srv-FICTIF-005", category_id=cat["Travail"],
        extra={"hostname": "srv.example", "port": "22", "protocol": "SSH"})
    add(service_name="Identité fictive", entry_type="identity", email="id@example.test",
        extra={"full_name": "Jean Dupont", "birth_date": "01/01/1990",
               "phone": "01 23 45 67 89", "id_number": "X0000000"},
        category_id=cat["Santé & Mutuelle"])
    orphan = add(service_name="Compte sans catégorie", url="https://orphelin.example",
                 username="orphelin", password="", category_id=doomed)
    categories.delete_category(doomed)  # the entry becomes "uncategorized"
    recent_trash = add(service_name="Ancien compte (corbeille)", username="ancien",
                       password="Old-FICTIF-006")
    old_trash = add(service_name="Très ancien compte (corbeille)", password="Old-FICTIF-007")
    entries.delete_entry(recent_trash)
    entries.delete_entry(old_trash)

    # History: 2 versions for the bank, 1 for the forum.
    for new_password in ("Mdp-Banque-FICTIF-001-b", "Mdp-Banque-FICTIF-001-c"):
        e = entries.get_entry(bank)
        e.password = new_password
        entries.update_entry(e)
    e = entries.get_entry(forum)
    e.username = "tux_renomme"
    e.url = "https://forum.example.org"
    entries.update_entry(e)
    del orphan

    # Entry moved to the Trash long ago (otherwise impossible to produce).
    with vault.connection as conn:
        conn.execute("UPDATE entries SET deleted_at = ? WHERE id = ?", (OLD_DELETION, old_trash))

    names = {c.id: c.name for c in categories.list_categories()}
    active = {s.id for s in entries.list_entries()}
    trashed = {s.id for s in entries.list_entries(EntryFilter(in_trash=True))}
    manifest_entries = []
    for entry_id in sorted(active | trashed):
        e = entries.get_entry(entry_id, include_deleted=True)
        history = [
            {"service_name": v.entry.service_name, "url": v.entry.url,
             "username": v.entry.username, "password": v.entry.password,
             "category_id": v.entry.category_id}
            for v in entries.list_history(entry_id)
        ]
        manifest_entries.append({
            "id": e.id, "entry_type": e.entry_type, "service_name": e.service_name,
            "url": e.url, "username": e.username, "email": e.email, "password": e.password,
            "notes": e.notes, "extra": e.extra, "category_id": e.category_id,
            "category": names.get(e.category_id) if e.category_id else None,
            "is_favorite": e.is_favorite, "in_trash": entry_id in trashed,
            "created_at": e.created_at, "updated_at": e.updated_at,
            "password_changed_at": e.password_changed_at, "deleted_at": e.deleted_at,
            "history": history,
        })

    filters = [
        {}, {"text": "banque"}, {"text": "EXEMPLE"}, {"text": "elephant"}, {"text": "café"},
        {"text": "tux"}, {"text": "finances"}, {"text": "srv"}, {"text": "sante"},
        {"text": "serveur debian"}, {"text": "inexistant"}, {"favorites_only": True},
        {"category_id": cat["Finances"]}, {"category_id": cat["Projets BTS"]},
        {"category_id": -1}, {"in_trash": True}, {"text": "ancien", "in_trash": True},
    ]
    searches = [{"filter": f, "result": [s.id for s in entries.list_entries(EntryFilter(**f))]}
                for f in filters]
    manifest = {
        "note": "Données 100 % fictives. Voir generate_v16_fixtures.py.",
        "app_version": __version__,
        "schema_version": database.SCHEMA_VERSION,
        "vault_id": VAULT_ID,
        "vault_name": VAULT_NAME,
        "master_password": MASTER_PASSWORD,
        "recovery_key": recovery_key,
        "categories": [{"id": c.id, "name": c.name, "is_builtin": c.is_builtin}
                       for c in categories.list_categories()],
        "entries": manifest_entries,
        "searches": searches,
    }
    db_path = Path(vault.connection.execute("PRAGMA database_list").fetchone()[2])
    vault.close()
    conn = sqlite3.connect(db_path)  # self-contained file: no -wal/-shm to ship
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    conn.close()

    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(db_path, out / "vault.db")
    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    shutil.rmtree(work)
    print(f"{out}: app {__version__}, schéma v{database.SCHEMA_VERSION}, "
          f"{len(manifest_entries)} entrées")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
