import re

with open("gui_app.py", "r") as f:
    content = f.read()

content = content.replace("from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl, QPoint, QPointF", "from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl, QPoint, QPointF, QSize")

init_old = """        # Action Buttons
        self.newBtn = QPushButton("New Folder")
        self.newBtn.setIcon(_icon("new-folder"))
        self.newBtn.clicked.connect(self.doMkFld)
        
        self.refBtn = QPushButton("Refresh")
        self.refBtn.setIcon(_icon("refresh"))
        self.refBtn.clicked.connect(self.doFlds)
        
        self.upBtn = QPushButton("Upload")
        self.upBtn.setIcon(_icon("upload"))
        self.upBtn.clicked.connect(self.doUpload)
        
        self.upDirBtn = QPushButton("Upload Dir")
        self.upDirBtn.setIcon(_icon("folder-upload"))
        self.upDirBtn.clicked.connect(self.doUpDir)
        
        self.dnBtn = QPushButton("Download")
        self.dnBtn.setIcon(_icon("download"))
        self.dnBtn.clicked.connect(self.doDown)
        
        self.viewBtn = QPushButton("View")
        self.viewBtn.setIcon(_icon("view"))
        self.viewBtn.clicked.connect(self.doView)"""

init_new = """        # Action Buttons
        self.refBtn = QPushButton("Refresh")
        self.refBtn.setIcon(_icon("refresh"))
        self.refBtn.clicked.connect(self.doFlds)
        
        self.newBtn = QPushButton("New Folder")
        self.newBtn.setIcon(_icon("new-folder"))
        self.newBtn.clicked.connect(self.doMkFld)
        
        self.upBtn = QPushButton("Upload")
        self.upBtn.setIcon(_icon("upload"))
        self.upBtn.clicked.connect(self.doUpload)
        
        self.upDirBtn = QPushButton("Upload Dir")
        self.upDirBtn.setIcon(_icon("folder-upload"))
        self.upDirBtn.clicked.connect(self.doUpDir)
        
        self.dnBtn = QPushButton("Download")
        self.dnBtn.setIcon(_icon("download"))
        self.dnBtn.clicked.connect(self.doDown)
        
        self.viewModeBtn = QPushButton("View")
        self.viewModeBtn.setIcon(_icon("view"))
        self.viewModeBtn.clicked.connect(self.doToggleViewMode)
        self.isIconView = False"""

content = content.replace(init_old, init_new)

content = content.replace("topLay.addWidget(self.viewBtn)", "topLay.addWidget(self.viewModeBtn)")

content_old = """        self.curLbl = QLabel("Select a folder")
        self.curLbl.setStyleSheet("font-size: 28px; font-weight: 700; color: #FFFFFF; margin-bottom: 10px; background: transparent; border: none;")

        self.fileTbl = QTableWidget(0, 3)
        self.fileTbl.setHorizontalHeaderLabels(["", "Filename", "Size"])
        self.fileTbl.setStyleSheet("background-color: transparent; border: none;")
        
        self.tableSpaceShortcut = QShortcut(QKeySequence(Qt.Key.Key_Space), self.fileTbl)
        self.tableSpaceShortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        self.tableSpaceShortcut.activated.connect(self.doView)
        
        self.fileTbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.fileTbl.setColumnWidth(0, 80)
        self.fileTbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.fileTbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.fileTbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.fileTbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.fileTbl.itemDoubleClicked.connect(self.doView)
        self.fileTbl.setSortingEnabled(True)
        self.fileTbl.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.fileTbl.verticalHeader().setDefaultSectionSize(26)
        self.fileTbl.verticalHeader().hide()"""

content_new = """        self.curLbl = QLabel("Select a folder")
        self.curLbl.setStyleSheet("font-size: 20px; font-weight: 700; color: #FFFFFF; margin-bottom: 10px; background: transparent; border: none;")

        from PyQt6.QtWidgets import QStackedWidget, QListWidget
        self.fileStack = QStackedWidget()

        self.fileTbl = QTableWidget(0, 3)
        self.fileTbl.setHorizontalHeaderLabels(["", "Filename", "Size"])
        self.fileTbl.setStyleSheet("background-color: transparent; border: none;")
        
        self.fileTbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.fileTbl.setColumnWidth(0, 40)
        self.fileTbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.fileTbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.fileTbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.fileTbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.fileTbl.itemDoubleClicked.connect(self.doView)
        self.fileTbl.setSortingEnabled(True)
        self.fileTbl.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.fileTbl.verticalHeader().setDefaultSectionSize(26)
        self.fileTbl.verticalHeader().hide()
        
        self.fileIconList = QListWidget()
        self.fileIconList.setViewMode(QListWidget.ViewMode.IconMode)
        self.fileIconList.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.fileIconList.setIconSize(QSize(64, 64))
        self.fileIconList.setSpacing(10)
        self.fileIconList.setStyleSheet("background-color: transparent; border: none; outline: 0;")
        self.fileIconList.itemDoubleClicked.connect(self.doView)
        
        self.fileStack.addWidget(self.fileTbl)
        self.fileStack.addWidget(self.fileIconList)

        self.tableSpaceShortcut = QShortcut(QKeySequence(Qt.Key.Key_Space), self.fileStack)
        self.tableSpaceShortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        self.tableSpaceShortcut.activated.connect(self.doView)"""

content = content.replace(content_old, content_new)

content = content.replace("ctLay.addWidget(self.fileTbl)", "ctLay.addWidget(self.fileStack)")

content = content.replace("self.curLbl.setText(f\"Folder: {self.curFld}\")", "self.curLbl.setText(self.curFld)")
content = content.replace("self.fileTbl.setRowCount(0)\n        self._wk = WkFiles(self.cli, self.curFld)", "self.fileTbl.setRowCount(0)\n        self.fileIconList.clear()\n        self._wk = WkFiles(self.cli, self.curFld)")
content = content.replace("self.fldList.clear()\n        self.fileTbl.setRowCount(0)", "self.fldList.clear()\n        self.fileTbl.setRowCount(0)\n        self.fileIconList.clear()")

onfiles_old = """    def _onFiles(self, pid, key, files):
        self.curPid = pid
        self.curKey = key
        self.curFiles = files
        self.proxy.updCtx(self.cli, files)
        self._thumbWk = []

        IMG = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'}
        VID = {'mp4', 'webm', 'mov', 'mkv'}
        TXT = {'txt', 'md', 'csv', 'py', 'json', 'log'}

        self.fileTbl.setSortingEnabled(False)
        self.fileTbl.setRowCount(0)

        for name, info in files.items():
            sz = Opsec.DecodeInt(info[44:52], False)
            row = self.fileTbl.rowCount()
            self.fileTbl.insertRow(row)
            self.fileTbl.setRowHeight(row, 70)

            thLbl = QLabel()
            thLbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''

            if ext in IMG | VID:
                if ext == 'svg':
                    thLbl.setText("🎨")
                else:
                    thLbl.setText("⏳")
                thLbl.setStyleSheet("color:#888; font-size:22px;")
                fk = info[:44]
                fpid = self.cli.objPid(fk)
                thLbl.setProperty("fpid", fpid)
                w = WkThumb(self.cli, pid, fpid, fk)
                w.success.connect(self._onThumb)
                w.start()
                self._thumbWk.append(w)
            elif ext == 'pdf':
                thLbl.setText("📄"); thLbl.setStyleSheet("font-size:32px;")
            elif ext in TXT:
                thLbl.setText("📝"); thLbl.setStyleSheet("font-size:32px;")
            else:
                thLbl.setText("📁"); thLbl.setStyleSheet("font-size:32px;")

            self.fileTbl.setCellWidget(row, 0, thLbl)
            self.fileTbl.setItem(row, 0, SortItem(""))

            nItem = SortItem(name)
            nItem.setData(Qt.ItemDataRole.UserRole, name.lower())
            sItem = SortItem(self._fmtSize(sz))
            sItem.setData(Qt.ItemDataRole.UserRole, sz)

            self.fileTbl.setItem(row, 1, nItem)
            self.fileTbl.setItem(row, 2, sItem)

        self.fileTbl.setSortingEnabled(True)
        self.doFilter(self.srchIn.text())"""

onfiles_new = """    def _onFiles(self, pid, key, files):
        self.curPid = pid
        self.curKey = key
        self.curFiles = files
        self.proxy.updCtx(self.cli, files)
        self._thumbWk = []

        IMG = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'}
        VID = {'mp4', 'webm', 'mov', 'mkv'}
        TXT = {'txt', 'md', 'csv', 'py', 'json', 'log'}

        self.fileTbl.setSortingEnabled(False)
        self.fileTbl.setRowCount(0)
        self.fileIconList.clear()

        from PyQt6.QtWidgets import QListWidgetItem
        for name, info in files.items():
            sz = Opsec.DecodeInt(info[44:52], False)
            row = self.fileTbl.rowCount()
            self.fileTbl.insertRow(row)
            self.fileTbl.setRowHeight(row, 26)

            thLbl = QLabel()
            thLbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
            
            iconItem = QListWidgetItem(name)
            iconItem.setData(Qt.ItemDataRole.UserRole, name.lower())
            iconItem.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            if ext in IMG | VID:
                if ext == 'svg':
                    thLbl.setText("🎨")
                else:
                    thLbl.setText("⏳")
                thLbl.setStyleSheet("color:#888; font-size:16px;")
                fk = info[:44]
                fpid = self.cli.objPid(fk)
                thLbl.setProperty("fpid", fpid)
                iconItem.setData(Qt.ItemDataRole.UserRole + 1, fpid)
                w = WkThumb(self.cli, pid, fpid, fk)
                w.success.connect(self._onThumb)
                w.start()
                self._thumbWk.append(w)
            elif ext == 'pdf':
                thLbl.setText("📄"); thLbl.setStyleSheet("font-size:18px;")
                iconItem.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
            elif ext in TXT:
                thLbl.setText("📝"); thLbl.setStyleSheet("font-size:18px;")
                iconItem.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
            else:
                thLbl.setText("📁"); thLbl.setStyleSheet("font-size:18px;")
                iconItem.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))

            self.fileTbl.setCellWidget(row, 0, thLbl)
            self.fileTbl.setItem(row, 0, SortItem(""))

            nItem = SortItem(name)
            nItem.setData(Qt.ItemDataRole.UserRole, name.lower())
            sItem = SortItem(self._fmtSize(sz))
            sItem.setData(Qt.ItemDataRole.UserRole, sz)

            self.fileTbl.setItem(row, 1, nItem)
            self.fileTbl.setItem(row, 2, sItem)
            self.fileIconList.addItem(iconItem)

        self.fileTbl.setSortingEnabled(True)
        self.fileIconList.sortItems()
        self.doFilter(self.srchIn.text())"""

content = content.replace(onfiles_old, onfiles_new)

onthumb_old = """    def _onThumb(self, fpid, raw):
        # QPixmap must be created on GUI thread
        pm = QPixmap.fromImage(QImage.fromData(raw))
        if pm.isNull():
            return
        scaled = pm.scaled(68, 68, Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
        # find row by fpid to handle sorting correctly
        for r in range(self.fileTbl.rowCount()):
            lbl = self.fileTbl.cellWidget(r, 0)
            if lbl and lbl.property("fpid") == fpid:
                lbl.setPixmap(scaled)
                break"""

onthumb_new = """    def _onThumb(self, fpid, raw):
        # QPixmap must be created on GUI thread
        pm = QPixmap.fromImage(QImage.fromData(raw))
        if pm.isNull():
            return
        scaled = pm.scaled(24, 24, Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
        for r in range(self.fileTbl.rowCount()):
            lbl = self.fileTbl.cellWidget(r, 0)
            if lbl and lbl.property("fpid") == fpid:
                lbl.setPixmap(scaled)
                break
                
        scaled_large = pm.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        for i in range(self.fileIconList.count()):
            it = self.fileIconList.item(i)
            if it.data(Qt.ItemDataRole.UserRole + 1) == fpid:
                it.setIcon(QIcon(scaled_large))
                break"""

content = content.replace(onthumb_old, onthumb_new)

dofilter_old = """    def doFilter(self, text):
        s = unicodedata.normalize('NFC', text).lower()
        for r in range(self.fileTbl.rowCount()):
            it = self.fileTbl.item(r, 1)
            if it:
                self.fileTbl.setRowHidden(r, s not in unicodedata.normalize('NFC', it.text()).lower())"""
dofilter_new = """    def doToggleViewMode(self):
        self.isIconView = not self.isIconView
        self.fileStack.setCurrentIndex(1 if self.isIconView else 0)

    def doFilter(self, text):
        s = unicodedata.normalize('NFC', text).lower()
        for r in range(self.fileTbl.rowCount()):
            it = self.fileTbl.item(r, 1)
            if it:
                self.fileTbl.setRowHidden(r, s not in unicodedata.normalize('NFC', it.text()).lower())
        for i in range(self.fileIconList.count()):
            it = self.fileIconList.item(i)
            it.setHidden(s not in unicodedata.normalize('NFC', it.text()).lower())"""

content = content.replace(dofilter_old, dofilter_new)

doview_old = """    def doView(self):
        sel = self.fileTbl.selectedItems()
        if not sel:
            return
        fn = self.fileTbl.item(sel[0].row(), 1).text()"""

doview_new = """    def doView(self):
        if self.isIconView:
            sel = self.fileIconList.selectedItems()
            if not sel:
                return
            fn = sel[0].text()
        else:
            sel = self.fileTbl.selectedItems()
            if not sel:
                return
            fn = self.fileTbl.item(sel[0].row(), 1).text()"""

content = content.replace(doview_old, doview_new)
content = content.replace("self.viewBtn.setEnabled(not on)", "self.viewModeBtn.setEnabled(not on)")

with open("gui_app.py", "w") as f:
    f.write(content)
