"""Vue « Sécurité » : score du coffre (méthode affichée), problèmes cliquables.

Le score n'est pas une mesure « scientifique » : c'est la part des comptes
pour lesquels l'audit local (app.core.audit) ne détecte aucun problème. La
vue l'affiche explicitement, avec la liste des contrôles effectués.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QBoxLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QPushButton,
    QVBoxLayout,
)

from app.core.audit import (
    KIND_EMPTY,
    KIND_EXPIRED_CARD,
    KIND_LABELS,
    KIND_OLD,
    KIND_REUSED,
    KIND_UNREADABLE,
    KIND_WEAK,
    AuditReport,
    run_audit,
)
from app.ui import components as ui
from app.ui import effects, theme
from app.ui.pages.base import AppContext, Page, scrolling

ISSUES = (
    (KIND_WEAK, "Mots de passe faibles", "Faciles à deviner : à remplacer.", "shield-alert",
     theme.DANGER),
    (KIND_REUSED, "Réutilisations", "Un même mot de passe sur plusieurs comptes.", "copy",
     theme.WARNING),
    (KIND_OLD, "Mots de passe anciens", "Inchangés depuis plus d'un an.", "clock", theme.INFO),
    (KIND_EMPTY, "Sans mot de passe", "Comptes dont le mot de passe est vide.", "key-round",
     theme.WARNING),
    (KIND_EXPIRED_CARD, "Cartes expirées", "Date d'expiration dépassée.", "credit-card",
     theme.INFO),
    (KIND_UNREADABLE, "Entrées illisibles", "Donnée chiffrée altérée.", "triangle-alert",
     theme.DANGER),
)


class _IssueCard(QFrame):
    clicked = Signal(str)

    def __init__(self, kind: str, title: str, text: str, icon: str, color: str) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.setCursor(Qt.PointingHandCursor)
        self.kind = kind
        self._color = color
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(14)
        self.icon = ui.icon_label(icon, color, 20)
        layout.addWidget(self.icon, 0, Qt.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.count = ui.label("0", "H2")
        self.count.setFont(theme.font(22, self.count.font().weight(), display=True))
        texts.addWidget(self.count)
        texts.addWidget(ui.label(title))
        texts.addWidget(ui.label(text, "Faint", wrap=True))
        layout.addLayout(texts, 1)
        layout.addWidget(ui.icon_label("chevron-right", theme.TEXT_3, 16), 0, Qt.AlignVCenter)

    def set_count(self, count: int, active: bool = False) -> None:
        effects.count_up(self.count, count)
        ok = count == 0
        self.setStyleSheet(f"QFrame#Card {{ border-color: {self._color}; }}" if active else "")
        self.setEnabled(not ok)
        self.setCursor(Qt.ArrowCursor if ok else Qt.PointingHandCursor)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.isEnabled():
            self.clicked.emit(self.kind)
        super().mouseReleaseEvent(event)


class SecurityPage(Page):
    key = "security"
    title = "Sécurité"
    subtitle = "Analyse locale de vos mots de passe"
    icon = "shield-check"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._report: AuditReport | None = None
        self._selected_kind: str | None = None
        layout = scrolling(self)

        # --- Recommandation : clé de récupération ----------------------------------------------
        self.recovery_card = ui.card("Card")
        self.recovery_card.setStyleSheet(f"QFrame#Card {{ border-color: {theme.WARNING}; }}")
        rec_row = QHBoxLayout(self.recovery_card)
        rec_row.setContentsMargins(18, 14, 18, 14)
        rec_row.setSpacing(14)
        rec_row.addWidget(ui.icon_label("key-round", theme.WARNING, 20), 0, Qt.AlignTop)
        rec_texts = QVBoxLayout()
        rec_texts.setSpacing(2)
        rec_texts.addWidget(ui.label("Aucune clé de récupération", "H2"))
        rec_texts.addWidget(ui.label(
            "Si vous oubliez le mot de passe maître, ce coffre sera définitivement perdu. "
            "Une clé de récupération, notée sur papier, permet d'en choisir un nouveau.",
            "Faint", wrap=True))
        rec_row.addLayout(rec_texts, 1)
        rec_row.addWidget(ui.button("Créer une clé", "key-round", "Primary",
                                    on_click=lambda: self.ctx.vault_action("recovery")),
                          0, Qt.AlignVCenter)
        self.recovery_card.hide()
        layout.addWidget(self.recovery_card)

        # Côte à côte sur une fenêtre large, empilés quand elle est étroite (moitié d'écran).
        top = self._top = QBoxLayout(QBoxLayout.LeftToRight)
        top.setSpacing(16)

        # --- Grande carte : score -------------------------------------------------------------
        score_card = ui.card("Surface")
        score_card.setMinimumWidth(330)
        score_layout = QVBoxLayout(score_card)
        score_layout.setContentsMargins(24, 22, 24, 22)
        score_layout.setSpacing(10)
        score_layout.addWidget(ui.label("ÉTAT DU COFFRE", "Overline"), 0, Qt.AlignHCenter)
        self.ring = ui.ScoreRing(188)
        score_layout.addWidget(self.ring, 0, Qt.AlignHCenter)
        self.level = ui.label("", "H2")
        self.level.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.level)
        self.method = ui.label("", "Faint", wrap=True)
        self.method.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.method)
        score_layout.addWidget(ui.button("Relancer l'analyse", "refresh-cw",
                                         on_click=self.run), 0, Qt.AlignHCenter)
        top.addWidget(score_card)

        # --- Problèmes -------------------------------------------------------------------------
        grid = QGridLayout()
        grid.setSpacing(12)
        self.issue_cards: dict[str, _IssueCard] = {}
        for i, (kind, title, text, icon, color) in enumerate(ISSUES):
            card = _IssueCard(kind, title, text, icon, color)
            card.clicked.connect(self._select_kind)
            grid.addWidget(card, i // 2, i % 2)
            self.issue_cards[kind] = card
        top.addLayout(grid, 1)
        layout.addLayout(top)

        # --- Détail d'un problème -----------------------------------------------------------------
        self.detail_card = ui.card()
        detail_layout = QVBoxLayout(self.detail_card)
        detail_layout.setContentsMargins(18, 16, 18, 14)
        detail_layout.setSpacing(4)
        self.detail_title = ui.section("Comptes concernés", "Cliquez sur un problème ci-dessus.")
        detail_layout.addWidget(self.detail_title)
        self.detail_rows = QVBoxLayout()
        self.detail_rows.setSpacing(2)
        detail_layout.addLayout(self.detail_rows)
        layout.addWidget(self.detail_card)

        methodology = ui.label(
            "Contrôles effectués localement, sans connexion : robustesse estimée de chaque mot "
            "de passe (motifs, dictionnaires, entropie), réutilisation entre comptes, ancienneté "
            "(plus d'un an), absence de mot de passe, cartes expirées, intégrité des données "
            "chiffrées. Dans la corbeille, seules les entrées dont les informations "
            "chiffrées (nom, adresse, identifiant…) sont illisibles sont signalées. Aucune "
            "vérification de fuite en ligne.",
            "Faint", wrap=True)
        layout.addWidget(methodology)
        layout.addStretch(1)

    _STACK_BELOW = 940  # largeur de vue sous laquelle le score passe au-dessus des problèmes

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        narrow = event.size().width() < self._STACK_BELOW
        self._top.setDirection(QBoxLayout.TopToBottom if narrow else QBoxLayout.LeftToRight)

    def refresh_recovery(self) -> None:
        if not self.ctx.vault.is_locked:
            self.recovery_card.setVisible(not self.ctx.vault.has_recovery_key)

    def on_show(self, **kwargs) -> None:
        self.refresh_recovery()
        self.level.setText("Analyse en cours…")
        QTimer.singleShot(0, self.run)

    def run(self) -> None:
        if self.ctx.vault.is_locked:
            return
        report = run_audit(self.ctx.entries)
        self._report = report
        flagged = len({f.entry_id for f in report.findings})
        healthy = report.checked_entries - flagged
        self.ring.set_score(report.score)
        if report.checked_entries == 0:
            self.level.setText("Coffre vide")
            self.method.setText("Ajoutez des comptes pour obtenir une analyse.")
        else:
            self.level.setText("Protection élevée" if report.score >= 80 else
                               "Protection moyenne" if report.score >= 50 else "Protection faible")
            self.method.setText(f"Part des comptes sans problème détecté : {healthy} sur "
                                f"{report.checked_entries}.")
        for kind, card in self.issue_cards.items():
            card.set_count(len(report.by_kind(kind)), kind == self._selected_kind)
        if self._selected_kind and report.by_kind(self._selected_kind):
            self._select_kind(self._selected_kind)
        else:
            first = next((k for k, *_ in ISSUES if report.by_kind(k)), None)
            if first:
                self._select_kind(first)
            else:
                self._show_rows([], "Aucun problème détecté",
                                "Tous vos comptes passent les contrôles.")

    def _select_kind(self, kind: str) -> None:
        if self._report is None:
            return
        self._selected_kind = kind
        for key, card in self.issue_cards.items():
            card.set_count(len(self._report.by_kind(key)), key == kind)
        findings = self._report.by_kind(kind)
        self._show_rows(findings, KIND_LABELS[kind],
                        f"{len(findings)} compte{'s' if len(findings) > 1 else ''} · cliquez "
                        "pour ouvrir")

    def _show_rows(self, findings, title: str, subtitle: str) -> None:
        self.detail_card.layout().replaceWidget(
            self.detail_title, new := ui.section(title, subtitle))
        self.detail_title.deleteLater()
        self.detail_title = new
        while self.detail_rows.count():
            item = self.detail_rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        rows = []
        for finding in findings:
            row = QPushButton()
            row.setObjectName("Ghost")
            row.setCursor(Qt.PointingHandCursor)
            row.setMinimumHeight(50)
            inner = QHBoxLayout(row)
            inner.setContentsMargins(10, 4, 12, 4)
            inner.setSpacing(12)
            inner.addWidget(ui.Avatar(finding.service_name, 32))
            inner.addWidget(ui.label(finding.service_name), 1)
            inner.addWidget(ui.label(finding.detail, "Faint"))
            inner.addWidget(ui.icon_label("chevron-right", theme.TEXT_3, 16))
            row.clicked.connect(lambda _c=False, i=finding.entry_id:
                                self.ctx.navigate("vault", entry_id=i))
            self.detail_rows.addWidget(row)
            rows.append(row)
        effects.stagger(rows)

