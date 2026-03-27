import os
import sys

from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
)


class ProjectVersionDialog(QDialog):
    """
    Dialog for selecting a Black Duck project and version.

    If project_name is empty, shows both a project list and a version list.
    If project_name is provided, skips the project list and loads versions directly.

    Public attributes after accept():
      selected_project  str – project name  (empty if project_name was pre-supplied)
      selected_version  str – version name
    """

    def __init__(self, bd, project_name: str = ''):
        self._app = QApplication.instance() or QApplication(sys.argv)
        super().__init__()
        self._bd = bd
        self._project_name = project_name
        self._projects: list[dict] = []   # [{name, href}]
        self._versions: list[dict] = []   # [{name, href}]

        self.selected_project: str = project_name
        self.selected_version: str = ''

        self.setWindowTitle('Black Duck – Select Project / Version')
        self.resize(600, 450)
        self._build_ui()

        if project_name:
            self._load_versions_for_project_name(project_name)
        else:
            self._load_projects()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        layout = QVBoxLayout(self)

        if not self._project_name:
            proj_group = QGroupBox('Project')
            proj_layout = QVBoxLayout(proj_group)
            self._proj_filter = QLineEdit()
            self._proj_filter.setPlaceholderText('Filter projects …')
            self._proj_filter.textChanged.connect(self._filter_projects)
            proj_layout.addWidget(self._proj_filter)
            self._proj_list = QListWidget()
            self._proj_list.currentItemChanged.connect(self._on_project_selected)
            proj_layout.addWidget(self._proj_list, stretch=1)
            layout.addWidget(proj_group, stretch=1)

        ver_group = QGroupBox('Version')
        ver_layout = QVBoxLayout(ver_group)
        self._ver_filter = QLineEdit()
        self._ver_filter.setPlaceholderText('Filter versions …')
        self._ver_filter.textChanged.connect(self._filter_versions)
        ver_layout.addWidget(self._ver_filter)
        self._ver_list = QListWidget()
        self._ver_list.currentItemChanged.connect(self._on_version_selected)
        ver_layout.addWidget(self._ver_list, stretch=1)
        layout.addWidget(ver_group, stretch=1)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_projects(self):
        try:
            url = f"{self._bd.base_url.rstrip('/')}/api/projects?limit=500&sort=name"
            data = self._bd.get_json(url)
            self._projects = [
                {'name': item['name'], 'href': item['_meta']['href']}
                for item in data.get('items', [])
                if item.get('name') and item.get('_meta', {}).get('href')
            ]
        except Exception as e:
            print(f"WARNING: error fetching projects: {e}", file=sys.stderr)

        self._proj_list.clear()
        for p in self._projects:
            self._proj_list.addItem(p['name'])

    def _load_versions(self, project_href: str):
        self._versions = []
        self._ver_list.clear()
        try:
            url = f"{project_href.rstrip('/')}/versions?limit=500&sort=versionName"
            data = self._bd.get_json(url)
            self._versions = [
                {'name': item['versionName'], 'href': item['_meta']['href']}
                for item in data.get('items', [])
                if item.get('versionName') and item.get('_meta', {}).get('href')
            ]
        except Exception as e:
            print(f"WARNING: error fetching versions: {e}", file=sys.stderr)

        for v in self._versions:
            self._ver_list.addItem(v['name'])

    def _load_versions_for_project_name(self, project_name: str):
        try:
            import urllib.parse
            url = (
                f"{self._bd.base_url.rstrip('/')}/api/projects"
                f"?q=name:{urllib.parse.quote(project_name)}&limit=10"
            )
            data = self._bd.get_json(url)
            for item in data.get('items', []):
                if item.get('name') == project_name:
                    self._load_versions(item['_meta']['href'])
                    break
        except Exception as e:
            print(f"WARNING: error fetching project '{project_name}': {e}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _filter_projects(self, text: str):
        query = text.lower()
        for i in range(self._proj_list.count()):
            item = self._proj_list.item(i)
            item.setHidden(query not in item.text().lower())

    def _filter_versions(self, text: str):
        query = text.lower()
        for i in range(self._ver_list.count()):
            item = self._ver_list.item(i)
            item.setHidden(query not in item.text().lower())

    def _on_project_selected(self, current, _previous):
        if not current:
            return
        self.selected_project = current.text()
        href = next((p['href'] for p in self._projects if p['name'] == self.selected_project), '')
        if href:
            self._load_versions(href)
        self.selected_version = ''
        self._update_ok()

    def _on_version_selected(self, current, _previous):
        self.selected_version = current.text() if current else ''
        self._update_ok()

    def _update_ok(self):
        ok = bool(self.selected_version)
        if not self._project_name:
            ok = ok and bool(self.selected_project)
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)


class KernelSourceDialog(QDialog):
    """
    Dialog for selecting the kernel source list file.

    Public attributes after accept():
      selected_file  str – absolute path to the chosen file
    """

    def __init__(self):
        self._app = QApplication.instance() or QApplication(sys.argv)
        super().__init__()
        self.selected_file: str = ''

        self.setWindowTitle('Black Duck – Select Kernel Source List File')
        self.resize(600, 120)
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        layout = QVBoxLayout(self)

        group = QGroupBox('Kernel Source List File')
        group_layout = QVBoxLayout(group)

        group_layout.addWidget(QLabel('Select the file containing the kernel source file/folder list:'))

        path_layout = QHBoxLayout()
        self._path_edit = QLineEdit()
        self._path_edit.setPlaceholderText('Path to kernel source list file …')
        self._path_edit.setReadOnly(True)
        path_layout.addWidget(self._path_edit, stretch=1)

        browse_btn = QPushButton('Browse …')
        browse_btn.clicked.connect(self._browse)
        path_layout.addWidget(browse_btn)
        group_layout.addLayout(path_layout)

        layout.addWidget(group)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            'Select Kernel Source List File',
            os.path.expanduser('~'),
            'All Files (*)',
        )
        if path and os.path.isfile(path):
            self._path_edit.setText(path)
            self.selected_file = path
            self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
